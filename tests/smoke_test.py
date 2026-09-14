#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IMAP 协议一致性冒烟测试（无 pytest 依赖）。

启动一个 headless 服务器子进程，用裸 socket 发送各类命令，并按 RFC 3501/9051 的
ABNF 校验应答：

  1. 每行以 CRLF 结束，首个 token 为 tag / "*" / "+"；
  2. 完成应答必须匹配  tag SP (OK|NO|BAD|PREAUTH) SP (resp-text)，且 text 非空；
  3. 字面量：同步 `{n}` 有 "+" 继续符，非同步 `{n+}` 不得索要，tag 跨续行不丢失；
  4. RFC 强制的 untagged 数据确实存在（CAPABILITY / EXISTS / LIST 根 / SEARCH / ENABLED）；
  5. IDLE 先 "+" 后 DONE 才完成；LOGOUT 先 * BYE；
  6. 超长行、非法 tag 等恶意输入只回 BAD，且服务不挂死。

用法：python3 tests/smoke_test.py
"""

import os
import re
import sys
import time
import socket
import contextlib
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, os.pardir, "src", "fake_imap_server.py")

# tag SP (OK|NO|BAD|PREAUTH) SP resp-text —— text 必填
DONE_RE = re.compile(rb"^[^\s]+ (OK|NO|BAD|PREAUTH)( \[.+\] .+| .+)$")
TAG_OK_RE = re.compile(rb"^(\S+) (OK|NO|BAD|PREAUTH)( .*)?$")

failures = []


def check(name, cond, detail=""):
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + ("" if cond else f"\n      ↳ 实际: {detail}"))
    if not cond:
        failures.append(name)


class Client:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=6)
        self.s.settimeout(6)
        self.buf = b""
        self.tag = 0

    def readline(self):
        while b"\n" not in self.buf:
            data = self.s.recv(65536)
            if not data:
                raise EOFError("connection closed by server")
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        if not line.endswith(b"\r"):
            raise AssertionError(f"未以 CRLF 结束: {line!r}")
        return line[:-1]

    def send(self, data):
        raw = data if isinstance(data, bytes) else data.encode()
        self.s.sendall(raw if raw.endswith(b"\r\n") else raw + b"\r\n")

    def next_tag(self):
        self.tag += 1
        return "A%03d" % self.tag

    def until_done(self, tag):
        """读到该 tag 的完成应答，返回 (untagged 行列表, 完成行)。"""
        untagged = []
        while True:
            line = self.readline()
            if line.startswith(tag.encode() + b" "):
                return untagged, line
            untagged.append(line)

    def cmd(self, command, collect=True):
        tag = self.next_tag()
        self.send(f"{tag} {command}")
        if not collect:
            return tag, [], self.readline()
        return tag, *self.until_done(tag)

    def close(self):
        with contextlib.suppress(OSError):
            self.s.close()


def grammar(lines, tag=None):
    for line in list(lines):
        if not line:
            return False, f"空响应行: {line!r}"
        first = line.split(b" ", 1)[0]
        if first not in (b"*", b"+") and (tag is None or first != tag.encode()):
            return False, f"首个 token 非法: {line!r}"
        if tag and first == tag.encode():
            if not DONE_RE.match(line):
                return False, f"完成应答不合法（resp-text 可能为空）: {line!r}"
    return True, ""


def free_port():
    with contextlib.closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_server(port, folders=None, extra=None):
    env = dict(os.environ, FAKE_IMAP_HEADLESS="1", FAKE_IMAP_PORT=str(port))
    if folders:
        env["FAKE_IMAP_FOLDERS"] = folders
    if extra:
        env.update(extra)
    return subprocess.Popen(
        [sys.executable, "-W", "ignore", SRC, "--headless", "--port", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def wait_port(port, proc, tries=120):
    for _ in range(tries):
        if proc.poll() is not None:
            raise SystemExit("服务器进程提前退出，无法测试")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return
        except OSError:
            time.sleep(0.05)
    raise SystemExit("服务器端口未就绪")


def main():
    port = free_port()
    proc = run_server(port)
    wait_port(port, proc)

    try:
        print("\n1. 问候语 / CAPABILITY")
        c = Client(port)
        greet = c.readline()
        check("问候语为 '* OK [CAPABILITY …] <text>'",
              greet.startswith(b"* OK [CAPABILITY ") and b"IMAP4rev1" in greet, greet)
        tag, u, done = c.cmd("CAPABILITY")
        check("CAPABILITY 带 untagged * CAPABILITY",
              any(l.startswith(b"* CAPABILITY ") for l in u), b" | ".join(u))
        check("完成应答语法合法（含非空 resp-text）",
              bool(DONE_RE.match(done)) and done.startswith(tag.encode()), done)

        print("\n2. 认证")
        tag, u, done = c.cmd("LOGIN anyone anything")
        check("任意凭据 → OK", done.startswith(b"A") and b" OK " in done, done)
        check("tag 区分大小写原样回显", done.split(b" ", 1)[0] == tag.encode(), done)
        check("成功 LOGIN 在 tagged OK 内带 [CAPABILITY]", b"[CAPABILITY" in done, done)
        tag, u, done = c.cmd("AUTHENTICATE PLAIN")
        check("AUTHENTICATE 回 NO（不吊住客户端等挑战）",
              done.startswith(tag.encode() + b" NO "), done)
        tag, u, done = c.cmd("STARTTLS")
        check("未声明 STARTTLS 时回 BAD", done.split(b" ")[1] == b"BAD", done)

        print("\n3. SELECT：selected 状态的必需 untagged 数据")
        tag, u, done = c.cmd("SELECT INBOX")
        body = b"\n".join(u)
        for need in (b"0 EXISTS", b"RECENT", b"* FLAGS (", b"[UIDVALIDITY 1]",
                     b"[UIDNEXT 1]", b"[PERMANENTFLAGS ("):
            check(f"含 '{need.decode(errors='replace')}'", need in body, body)
        check("SELECT → [READ-WRITE]", b"[READ-WRITE]" in done, done)
        tag, u, done = c.cmd("EXAMINE INBOX")
        check("EXAMINE → [READ-ONLY]", b"[READ-ONLY]" in done, done)
        tag, u, done = c.cmd("FETCH 1 (FLAGS BODY[])")
        check("EXISTS=0 时 FETCH 回 NO（不伪造条目）",
              done.split(b" ")[1] == b"NO", done)

        print("\n4. 命名空间 / 空结果")
        tag, u, done = c.cmd('LIST "" ""')
        check('根查询回 \'* LIST (\\Noselect) "/" ""\'',
              b'* LIST (\\Noselect) "/" ""' in b"\n".join(u), b"\n".join(u))
        tag, u, done = c.cmd("SEARCH UNSEEN")
        check("SEARCH 空结果仍有 '* SEARCH'", b"* SEARCH" in b"\n".join(u), b"\n".join(u))
        tag, u, done = c.cmd("STATUS INBOX (MESSAGES UNSEEN)")
        check("STATUS 回 MESSAGES 0 / UIDNEXT 1",
              b"MESSAGES 0" in b"\n".join(u) and b"UIDNEXT 1" in b"\n".join(u),
              b"\n".join(u))
        tag, u, done = c.cmd("NAMESPACE")
        check('NAMESPACE 三元组 \'(("" "/")) NIL NIL\'',
              b'* NAMESPACE (("" "/")) NIL NIL' in b"\n".join(u), b"\n".join(u))
        tag, u, done = c.cmd("ENABLE")
        check("ENABLE 的 untagged 是 '* ENABLED'（RFC 5161）",
              b"* ENABLED" in b"\n".join(u), b"\n".join(u))
        tag, u, done = c.cmd('ID ("name" "probe")')
        check("ID 回 untagged * ID (…)（RFC 2971，不得是 * NIL (…)）",
              any(l.startswith(b'* ID ("name"') for l in u), b"\n".join(u))
        tag, u, done = c.cmd("UID SEARCH ALL")
        check("UID 前缀被正确剥离并回 OK", done.startswith(b"A") and b" OK " in done, done)
        tag, u, done = c.cmd("GETQUOTA """)
        check("GETQUOTA 空应答合法", bool(DONE_RE.match(done)), done)

        print("\n5. IDLE（RFC 2177）")
        tag = c.next_tag()
        c.send(f"{tag} IDLE")
        cont = c.readline()
        check("先收到 '+ idling' 继续应答", cont.startswith(b"+ ") and len(cont) > 2, cont)
        c.send("DONE")
        done = c.readline()
        check("DONE 之后才发完成应答", done.startswith(tag.encode() + b" OK"), done)
        tag, u, done = c.cmd("NOOP")
        check("IDLE 结束后流仍同步（后续命令正常）", bool(DONE_RE.match(done)), done)

        print("\n6. 字面量：tag 不得丢失（旧实现在此挂死）")
        tag = c.next_tag()
        c.send(f"{tag} APPEND INBOX \\Seen {{5}}")
        cont = c.readline()
        check("同步字面量回 '+ go ahead'", cont.startswith(b"+ "), cont)
        c.send(b"hello")                    # 5 字节字面量 + CRLF
        done = c.readline()
        check(f"{tag} 被正确回显（未挂死、未丢 tag）",
              done.startswith(tag.encode() + b" OK"), done)

        tag = c.next_tag()
        c.send(f"{tag} APPEND INBOX {{2+}}\r\nhi\r\n")   # LITERAL+：一次管道发出
        lines = []
        with contextlib.suppress(Exception):
            while True:
                line = c.readline()
                lines.append(line)
                if line.startswith(tag.encode() + b" "):
                    break
        check("非同步字面量 {n+} 不索要 '+'", b"go ahead" not in b" ".join(lines), lines)
        check("LITERAL+ 命令仍被正确完成",
              any(l.startswith(tag.encode() + b" OK") for l in lines), b" | ".join(lines))

        print("\n7. 语法鲁棒性（RFC 9051 §2.2.1 SHOULD strictly enforce）")
        tag, u, done = c.cmd("NOOP")
        check("异常输入后连接仍然健康", done.startswith(b"A") and b" OK " in done, done)
        c.send("bad+tag NOOP")               # tag 含 '+'，违反 ABNF
        line = c.readline()
        check("含 '+' 的 tag → BAD（且连接保持可用）", line.endswith(b"BAD malformed tag"), line)
        c.send("A999")                       # 只有 tag、无命令名
        line = c.readline()
        check("缺命令名 → 回 tagged BAD（不让客户端空等）",
              line.startswith(b"A999 BAD ") and len(line) > 9, line)
        c.send("")                           # 裸 CRLF：连 tag 都没有
        line = c.readline()
        check("空行 → untagged '* BAD'", line.startswith(b"* BAD "), line)
        ok, why = grammar([line])
        check("该行语法仍合法（'*' 开头 + text 非空）", ok, why)
        c.send("A1000 NOOP " + "x" * 40000)  # 超长行
        got = []
        with contextlib.suppress(Exception):
            for _ in range(3):
                got.append(c.readline())
        check("超长行被拒绝（* BYE）且不崩", any(b"BYE" in g or b"BAD" in g for g in got),
              b" | ".join(got))
        c.close()

        print("\n8. 并发与不拖死")
        conns = []
        try:
            for _ in range(24):
                cc = Client(port)
                cc.readline()
                conns.append(cc)
            c2 = Client(port)
            c2.readline()
            tag, u, done = c2.cmd("NOOP")
            check("24 个空闲连接下仍能正常应答", bool(DONE_RE.match(done)), done)
            c2.close()
        finally:
            for cc in conns:
                cc.close()

        c3 = Client(port)
        c3.readline()
        tag, u, done = c3.cmd("LOGOUT")
        check("LOGOUT 先 '* BYE' 再 tagged OK",
              any(l.startswith(b"* BYE") for l in u) and done.startswith(tag.encode() + b" OK"),
              b" | ".join(u + [done]))
        with contextlib.suppress(OSError):
            closed = c3.s.recv(10) == b""
        check("LOGOUT 后服务器主动关闭连接", closed, "still open")
        c3.close()

        print("\n9. 邮箱列表 / 通配符 / LSUB / EXPUNGE（带 FAKE_IMAP_FOLDERS）")
        port2 = free_port()
        proc2 = run_server(port2, folders="INBOX,Sent,Projects/Work,Sent Items")
        wait_port(port2, proc2)
        try:
            cf = Client(port2)
            cf.readline()
            tag, u, done = cf.cmd('LIST "" "Sent"')
            body = b"\n".join(u)
            check('LIST "" "Sent" 只回 Sent（按 pattern 过滤）',
                  b"Sent" in body and b"INBOX" not in body
                  and b"Projects/Work" not in body, body)
            tag, u, done = cf.cmd('LIST "" "%"')
            body = b"\n".join(u)
            check('LIST "" "%" 不跨分隔符（不含 Projects/Work）',
                  b"INBOX" in body and b"Sent" in body
                  and b"Projects/Work" not in body, body)
            tag, u, done = cf.cmd('LIST "" ""')
            check('根查询仍回 \\Noselect 根',
                  b'* LIST (\\Noselect) "/" ""' in b"\n".join(u), b"\n".join(u))
            tag, u, done = cf.cmd('STATUS "Sent Items" (MESSAGES UNSEEN)')
            check('STATUS 正确回显带空格邮箱名（无嵌套引号）',
                  b'* STATUS "Sent Items" (' in b"\n".join(u), b"\n".join(u))
            tag, u, done = cf.cmd('LSUB "" "*"')
            check('LSUB 的 untagged 是 * LSUB（不是 * LIST）',
                  any(l.startswith(b"* LSUB ") for l in u), b"\n".join(u))
            tag, u, done = cf.cmd("EXPUNGE")
            check('空邮箱 EXPUNGE 不产生 "* 0 EXPUNGE"',
                  not any(b"EXPUNGE" in l for l in u), b"\n".join(u))
            cf.close()
        finally:
            proc2.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc2.wait(5)
            if proc2.poll() is None:
                proc2.kill()

        print("\n10. 状态机（ENFORCE_STATE=1）与含通配符的邮箱名")
        port3 = free_port()
        proc3 = run_server(port3, folders="INBOX,Foo*Bar",
                           extra={"FAKE_IMAP_ENFORCE_STATE": "1"})
        wait_port(port3, proc3)
        try:
            ce = Client(port3)
            ce.readline()
            tag, u, done = ce.cmd("LOGIN u p")
            check("LOGIN 成功", b" OK " in done, done)
            tag, u, done = ce.cmd('LIST "" "*"')
            check('邮箱名含 "*" 时回显为带引号 qstring',
                  b'"Foo*Bar"' in b"\n".join(u), b"\n".join(u))
            tag, u, done = ce.cmd("NAMESPACE")
            check("已认证态 NAMESPACE 可用（RFC 9051）",
                  b"* NAMESPACE" in b"\n".join(u), b"\n".join(u))
            tag = ce.next_tag()
            ce.send(f"{tag} IDLE")
            cont = ce.readline()
            check("已认证态 IDLE 可用（RFC 2177，不要求 selected）",
                  cont.startswith(b"+ "), cont)
            ce.send("DONE")
            done = ce.readline()
            check("IDLE 正常结束", done.startswith(tag.encode() + b" OK"), done)
            tag, u, done = ce.cmd("LOGIN u p")
            check("已认证态再 LOGIN → BAD（command-nonauth）",
                  done.split(b" ")[1] == b"BAD", done)
            ce.close()
        finally:
            proc3.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc3.wait(5)
            if proc3.poll() is None:
                proc3.kill()

        time.sleep(0.2)
        check("进程未因异常输入退出", proc.poll() is None, f"exit={proc.poll()}")

    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(5)
        if proc.poll() is None:
            proc.kill()

    print()
    if failures:
        print(f"\033[31m✗ {len(failures)} 项未通过\033[0m  " + ", ".join(failures))
        return 1
    print("\033[32m✓ 全部通过：应答语法与必需 untagged 数据均符合 RFC 3501/9051\033[0m")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print(f"\033[31m✗ 校验失败: {exc}\033[0m")
        sys.exit(1)
