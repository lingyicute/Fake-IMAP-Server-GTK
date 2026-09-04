#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fake IMAP Server
----------------
接受任意 IMAP 请求并进行「空应答」的假 IMAP 服务；GTK4 小窗口显示
“Fake IMAP Server 正在运行”，关闭窗口即终止进程。

协议实现要点（RFC 3501 / RFC 9051）
===================================
* 语法：所有响应行以 CRLF 结尾；完成应答形如
      tag SP ("OK"|"NO"|"BAD"|"PREAUTH") SP resp-text
  其中 `resp-text = ["[" resp-code "]" SP] text`，而 `text = 1*TEXT-CHAR` 为**必填**，
  因此绝不发送裸的 "<tag> OK"（那是语法错误）。
* tag：RFC 9051 `tag = ASTRING-CHAR - "+"`（RFC 3501：可打印 US-ASCII 且不含 '+'）。
  服务器区分大小写地原样回显客户端 tag，且**跨字面量续行**仍能正确取到 tag。
* 续行：`continue-req = "+" SP (resp-text / base64) CRLF`；同步字面量 `{n}` 前先回 "+"，
  非同步字面量 `{n+}`（LITERAL+）不索要继续符；字面量之后的字节会拼接回当前命令。
* 「空应答」的边界：对**没有强制 untagged 数据**的命令只回 "<tag> OK <text>"；
  对 RFC **要求**必须携带 untagged 数据的命令（SELECT/EXAMINE 的 EXISTS/RECENT/FLAGS/
  UIDVALIDITY/UIDNEXT，SEARCH 的 * SEARCH，LIST 的根分隔符，STATUS、NAMESPACE、
  ENABLED、ID、MYRIGHTS、IDLE 的 "+"、LOGOUT 的 * BYE）给出语法完整但内容为空的
  最小骨架 —— 省略它们不是“空应答”，而是协议错误。
* 不谎称拥有消息：SELECT 后 EXISTS=0，故 FETCH/STORE/COPY 回 NO，
  这是空邮箱下唯一合规的应答。
* 严格校验语法（RFC 9051 §2.2.1 "Servers SHOULD strictly enforce the syntax"）：
  非法 tag / 缺命令名 → BAD；无 tag 的行 → untagged `* BAD`（§7.1 允许）。

环境变量
--------
  FAKE_IMAP_HOST         监听地址，默认 127.0.0.1
  FAKE_IMAP_PORT         监听端口，默认 1143（0 = 随机端口）
  FAKE_IMAP_HEADLESS     1/true 不创建 GTK4 窗口（纯服务，便于 CI/测试）
  FAKE_IMAP_FOLDERS      逗号分隔的邮箱列表，默认空 = 服务器真的没有任何邮箱
  FAKE_IMAP_ENFORCE_STATE
                         1 = 严格状态机（未登录执行 select 阶段命令回 BAD）
  FAKE_IMAP_READ_TIMEOUT 命令间空闲秒数，默认 1800（超时回 * BYE 并断开）
  FAKE_IMAP_IDLE_TIMEOUT IDLE 最长保持秒数，默认 1800（到期正常结束 IDLE）
"""

import os
import re
import sys
import time
import select
import signal
import socket
import threading
import contextlib
import socketserver

# ------------------------------------------------------------------ 配置

APP_ID = "uk._92li.fakeimap.FakeImapServer"
APP_NAME = "Fake IMAP Server"
VERSION = "1.0.0"


def _flag(name, default=""):
    return os.environ.get(name, default).strip()


def _bool(name):
    return _flag(name).lower() in ("1", "true", "yes", "on")


HOST = _flag("FAKE_IMAP_HOST", "127.0.0.1") or "127.0.0.1"
PORT = int(_flag("FAKE_IMAP_PORT", "1143") or 1143)
HEADLESS = _bool("FAKE_IMAP_HEADLESS")
ENFORCE_STATE = _bool("FAKE_IMAP_ENFORCE_STATE")
READ_TIMEOUT = float(_flag("FAKE_IMAP_READ_TIMEOUT", "1800"))
IDLE_TIMEOUT = float(_flag("FAKE_IMAP_IDLE_TIMEOUT", "1800"))
FOLDERS = [f.strip() for f in _flag("FAKE_IMAP_FOLDERS").split(",") if f.strip()]

MAX_LINE = 8192            # 单行命令上限
MAX_LITERAL = 32 << 20     # 单个字面量上限
MAX_CONCURRENT = 128       # 并发连接上限

# 只声明真正实现了的命令，避免“谎报能力”导致客户端走进未支持路径
CAPABILITIES = "IMAP4rev1 LITERAL+ ENABLE IDLE NAMESPACE UNSELECT ID"

LITERAL_RE = re.compile(r"\{(\d+)(\+?)\}$")
# 可打印 US-ASCII，不含 '+'（RFC 3501 对 tag 的注释 / RFC 9051: ASTRING-CHAR - "+"）
TAG_RE = re.compile(rb"^[\x21-\x2a\x2c-\x7e]+$")

STATS = {"connections": 0, "commands": 0, "bytes": 0}
_LOCK = threading.Lock()

PRE_AUTH, AUTH, SELECTED = 0, 1, 2

ANY_STATE = {"CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "AUTHENTICATE",
             "LOGIN", "ENABLE", "ID"}
NEED_AUTH = {"SELECT", "EXAMINE", "CREATE", "DELETE", "RENAME", "SUBSCRIBE",
             "UNSUBSCRIBE", "LIST", "LSUB", "STATUS", "APPEND", "MYRIGHTS",
             "LISTRIGHTS", "GETQUOTA", "GETQUOTAROOT", "SETQUOTA"}
NEED_SELECTED = {"SEARCH", "FETCH", "STORE", "COPY", "EXPUNGE", "CHECK",
                 "CLOSE", "UNSELECT", "SORT", "THREAD", "IDLE", "MOVE"}


def _b(s):
    return s.encode("utf-8", "surrogateescape") if isinstance(s, str) else s


def _quote(tok):
    """把 token 变成合法的 astring / qstring（必要时加引号并转义）。"""
    tok = (tok or b"").strip()
    if not tok:
        return b'""'
    if tok.upper() == b"NIL":
        return b"NIL"
    safe = all(0x21 <= c <= 0x7E and c not in b'"\\(){}[]% ' for c in tok)
    if safe and not tok.isdigit():
        return tok
    return b'"' + tok.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


class SyntaxViolation(Exception):
    """单条命令的语法错误：只回 BAD，不切断连接（客户端仍能复用会话）。"""

    def __init__(self, tag, text):
        self.tag = tag
        super().__init__(text)


# -------------------------------------------------------- 带超时的行读取器

class LineReader:
    """自己管理缓冲的行/字节读取器。

    不用 socketserver 的 rfile（BufferedReader）：一旦在缓冲读中途抛 socket.timeout，
    缓冲区就会与服务端流错位。这里每字节都自己数，超时后可安全地继续或断开。
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""
        self.eof = False

    def _fill(self, deadline):
        if len(self.buf) > 4 * MAX_LINE and b"\n" not in self.buf:
            raise ValueError("command line too long")
        timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            raise TimeoutError("idle timeout")
        data = self.sock.recv(65536)
        if not data:
            self.eof = True
            return False
        with _LOCK:
            STATS["bytes"] += len(data)
        self.buf += data
        return True

    def read_line(self, deadline):
        """返回去掉 CRLF 的一行；对端关闭返回 None。"""
        while b"\n" not in self.buf:
            if not self._fill(deadline):
                self.buf = b""      # 未以 CRLF 结束的半行不是合法命令，直接丢弃
                return None
        line, self.buf = self.buf.split(b"\n", 1)
        line = line[:-1] if line.endswith(b"\r") else line
        if len(line) > MAX_LINE:
            raise ValueError("command line too long")
        return line

    def read_exact(self, n, deadline):
        """读取并丢弃 n 字节（IMAP 字面量内容）。"""
        while n > 0:
            while len(self.buf) < n:
                if not self._fill(deadline):
                    raise ValueError("connection closed during literal")
            take = min(n, len(self.buf))
            self.buf = self.buf[take:]
            n -= take


# --------------------------------------------------------------- IMAP 部分

class FakeImapHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.sock = self.request
        with contextlib.suppress(OSError):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.reader = LineReader(self.sock)
        self.state = PRE_AUTH
        self.deadline = None
        self.peer = "%s:%s" % self.client_address[:2]

    # ---------------- 输出 ----------------
    def send(self, line: bytes):
        self.sock.sendall(line if line.endswith(b"\r\n") else line + b"\r\n")

    def done(self, tag, status, text, code=None):
        """构造一条完成应答，保证 text 非空（ABNF 要求）。"""
        line = tag + b" " + status
        if code:
            line += b" [" + _b(code) + b"]"
        text = _b(text).strip() if text else b""
        line += b" " + (text or b"completed")
        self.send(line)

    def ok(self, tag, text="completed", code=None):
        self.done(tag, b"OK", text, code)

    def no(self, tag, text="not supported", code=None):
        self.done(tag, b"NO", text, code)

    def bad(self, tag, text="invalid command"):
        self.done(tag, b"BAD", text)

    # ---------------- 输入 ----------------
    def read_command(self):
        """读取一条完整命令 → (tag, NAME, args)；对端关闭 → None。"""
        cmd = b""
        while True:
            line = self.reader.read_line(self.deadline)
            if line is None:
                return None
            m = LITERAL_RE.search(line.decode("latin-1"))
            if not m:
                cmd += (b" " if cmd else b"") + line
                break
            size = int(m.group(1))
            if size > MAX_LITERAL:
                raise ValueError("literal too large")
            cmd += (b" " if cmd else b"") + line[:m.start()]
            if not m.group(2):                       # 同步字面量：先索要后续数据
                self.send(b"+ go ahead")
            self.reader.read_exact(size, self.deadline)

        fields = cmd.split(None, 2)
        if not fields:
            return b"", b"", b""
        tag = fields[0]
        name = fields[1].upper() if len(fields) > 1 else b""
        args = fields[2] if len(fields) > 2 else b""
        if tag in (b"+", b"-") or not TAG_RE.match(tag):
            # RFC 3501: tag 是可打印 US-ASCII 且不含 '+'；违反时回 BAD 而不是断开
            raise SyntaxViolation(tag, "malformed tag")
        return tag, name, args

    # ---------------- 主循环 ----------------
    def handle(self):
        with _LOCK:
            STATS["connections"] += 1
        print(f"[+] connect {self.peer}", flush=True)
        # 问候语带 [CAPABILITY]，省掉客户端一发 CAPABILITY 往返（§7.2.1 允许）
        self.ok(b"*", f"{APP_NAME} ready", code="CAPABILITY " + CAPABILITIES)

        try:
            while True:
                self.deadline = time.monotonic() + READ_TIMEOUT
                try:
                    cmd = self.read_command()
                except SyntaxViolation as e:
                    # 只拒绝这一条命令，保持连接可用（tag 非法时退化为 untagged BAD）
                    self.done(e.tag or b"*", b"BAD", str(e) or "syntax error")
                    continue
                except (TimeoutError, ValueError) as e:
                    self.send(b"* BYE [ALERT] " + _b(f"{APP_NAME}: {e}"))
                    return
                if cmd is None:
                    return
                tag, name, args = cmd
                if not name:
                    # 只有 tag 没有命令名：仍回 tagged BAD，否则客户端会一直等完成应答
                    if tag:
                        self.bad(tag, "missing command name")
                    else:
                        self.send(b"* BAD invalid command; missing command name")
                    continue
                with _LOCK:
                    STATS["commands"] += 1
                shown = f"{tag.decode('latin-1')} {name.decode('latin-1')} {args.decode('latin-1')[:100]}".strip()
                print(f"[>] {self.peer} {shown}", flush=True)
                if not self.dispatch(tag, name, args):
                    return
        except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
            pass
        finally:
            print(f"[-] disconnect {self.peer}", flush=True)

    def dispatch(self, tag, name, args):
        """返回 False 表示应当关闭连接。"""
        uid = False
        if name == b"UID":                    # `UID FETCH` 等：真正的命令在 args 里
            head = args.split(None, 1)
            if not head:
                self.bad(tag, "UID requires a command")
                return True
            name = head[0].upper()
            args = head[1] if len(head) > 1 else b""
            uid = True

        name_s = name.decode("latin-1")
        if name_s == "LOGOUT":
            self.send(b"* BYE " + _b(f"{APP_NAME} signing off"))
            self.ok(tag, "LOGOUT completed")
            return False

        if ENFORCE_STATE:
            if name_s in NEED_SELECTED and self.state != SELECTED:
                self.bad(tag, f"{name_s} invalid in "
                              f"{'authenticated' if self.state == AUTH else 'not authenticated'} state")
                return True
            if name_s in NEED_AUTH and self.state == PRE_AUTH:
                self.bad(tag, f"{name_s} invalid in unauthenticated state")
                return True

        handler = getattr(self, "cmd_" + re.sub(r"\W", "", name_s.lower()), None)
        try:
            if handler:
                handler(tag, args, uid)
            else:
                self.ok(tag, f"{name_s} completed")   # ← 「空应答」：只确认，不带数据
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False
        return True

    # ---------------- 命令实现 ----------------
    def cmd_capability(self, tag, args, uid):
        self.send(b"* CAPABILITY " + _b(CAPABILITIES))
        self.ok(tag, "CAPABILITY completed")

    def cmd_login(self, tag, args, uid):
        self.state = AUTH
        # §7.2.1：成功认证时在 tagged OK 里带上更新后的 CAPABILITY
        self.ok(tag, "LOGIN completed", code="CAPABILITY " + CAPABILITIES)

    def cmd_authenticate(self, tag, args, uid):
        # 不实现任何 SASL 机制。直接回 OK 会让客户端苦等挑战数据（协议错误），
        # 所以回 NO，客户端会自动回落到 LOGIN。
        self.no(tag, "no supported SASL mechanisms offered")

    def cmd_select(self, tag, args, uid, examine=False):
        # §6.3.1：进入 selected 状态前**必须**发送 EXISTS/RECENT/FLAGS，
        # 且客户端必须能拿到 UIDVALIDITY/UIDNEXT。空邮箱 → 全 0/1。
        self.send(b"* 0 EXISTS")
        self.send(b"* 0 RECENT")
        self.send(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
        self.send(b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Limited")
        self.send(b"* OK [UIDVALIDITY 1] UIDs valid")
        self.send(b"* OK [UIDNEXT 1] Predicted next UID")
        self.send(b"* OK [HIGHESTMODSEQ 0] Highest")
        self.state = SELECTED
        self.ok(tag, f"{'EXAMINE' if examine else 'SELECT'} completed",
                code="READ-ONLY" if examine else "READ-WRITE")

    def cmd_examine(self, tag, args, uid):
        self.cmd_select(tag, args, uid, examine=True)

    def _leave_selected(self, tag, text):
        self.state = AUTH
        self.ok(tag, text)

    def cmd_close(self, tag, args, uid):
        self._leave_selected(tag, "CLOSE completed")

    def cmd_unselect(self, tag, args, uid):
        self._leave_selected(tag, "UNSELECT completed")

    def cmd_expunge(self, tag, args, uid):
        self.send(b"* 0 EXPUNGE")
        self.ok(tag, "EXPUNGE completed")

    def _list_line(self, name: bytes):
        self.send(b'* LIST (\\HasNoChildren) "/" ' + _quote(name))

    def cmd_list(self, tag, args, uid, lsub=False):
        # 解析 reference / pattern（宽松处理：取末尾两个带引号/裸 token）
        pattern = b""
        toks = args.replace(b'"', b"").split()
        if len(toks) >= 2:
            pattern = toks[-1]
        kind = "LSUB" if lsub else "LIST"
        if lsub and not FOLDERS:
            self.ok(tag, "LSUB completed")            # 未订阅任何邮箱：空结果合规
            return
        # `LIST "" ""` 是根查询，必须回分隔符（§6.3.8）；模式 "*" 也匹配空根名，
        # 因此“一个邮箱都没有”时仍要给出 \Noselect 根，而不是彻底空列表。
        if not pattern or pattern == b"*":
            self.send(b'* LIST (\\Noselect) "/" ""')
        for f in FOLDERS:
            self._list_line(_b(f))
        self.ok(tag, f"{kind} completed")

    def cmd_lsub(self, tag, args, uid):
        self.cmd_list(tag, args, uid, lsub=True)

    def cmd_status(self, tag, args, uid):
        mailbox = _quote(args.split(b"[")[0].split(b"(")[0].split()[-1]
                         if args.split() else b"INBOX")
        self.send(b'* STATUS ' + mailbox +
                  b" (MESSAGES 0 UNSEEN 0 UIDNEXT 1 UIDVALIDITY 1 HIGHESTMODSEQ 0)")
        self.ok(tag, "STATUS completed")

    def cmd_search(self, tag, args, uid):
        self.send(b"* SEARCH")                         # 空结果也必须有这一行
        self.ok(tag, "SEARCH completed")

    def cmd_sort(self, tag, args, uid):
        self.send(b"* SORT")
        self.ok(tag, "SORT completed")

    def cmd_thread(self, tag, args, uid):
        self.send(b"* THREAD")
        self.ok(tag, "THREAD completed")

    def cmd_namespace(self, tag, args, uid):
        self.send(b'* NAMESPACE (("" "/")) NIL NIL')
        self.ok(tag, "NAMESPACE completed")

    def cmd_myrights(self, tag, args, uid):
        mailbox = _quote(args.split()[0] if args.split() else b"INBOX")
        self.send(b"* MYRIGHTS " + mailbox + b' "lksatwen"')
        self.ok(tag, "MYRIGHTS completed")

    def cmd_listrights(self, tag, args, uid):
        mailbox = _quote(args.split()[0] if args.split() else b"INBOX")
        self.send(b'* LISTRIGHTS ' + mailbox + b' "" "l kx s a t w n e"')
        self.ok(tag, "LISTRIGHTS completed")

    def cmd_enable(self, tag, args, uid):
        # RFC 5161: untagged 形式是 "* ENABLED <cap>"（不是 * ENABLE），即使为空
        self.send(b"* ENABLED")
        self.ok(tag, "ENABLE completed")

    def cmd_id(self, tag, args, uid):
        # RFC 2971：以 untagged * NIL 回应字段列表
        self.send(b'* NIL ("name" "' + _b(APP_NAME) + b'" "vendor" "fake-imap" '
                  b'"version" "' + _b(VERSION) + b'")')
        self.ok(tag, "ID completed")

    def cmd_idle(self, tag, args, uid):
        # RFC 2177：先回 "+" 继续符；收到 DONE 才能发完成应答
        self.send(b"+ idling")
        deadline = time.monotonic() + IDLE_TIMEOUT
        while True:
            try:
                line = self.reader.read_line(deadline)
            except TimeoutError:
                self.ok(tag, "IDLE terminated (timeout)")
                return
            except ValueError:
                self.ok(tag, "IDLE terminated")
                return
            if line is None:
                raise OSError("closed during IDLE")
            if line.strip().upper() == b"DONE":
                break
        self.ok(tag, "IDLE completed")

    def cmd_append(self, tag, args, uid):
        self.ok(tag, "APPEND completed")      # 字面量已在 read_command 中完整吞掉

    def cmd_fetch(self, tag, args, uid):
        self.no(tag, "no messages exist in this mailbox")

    def cmd_store(self, tag, args, uid):
        self.no(tag, "no messages exist in this mailbox")

    def cmd_copy(self, tag, args, uid):
        self.no(tag, "no messages exist in this mailbox")

    def cmd_starttls(self, tag, args, uid):
        self.bad(tag, "STARTTLS is not advertised by this server")

    def cmd_compress(self, tag, args, uid):
        self.bad(tag, "COMPRESS=DEFLATE not supported")

    def cmd_noop(self, tag, args, uid):
        self.ok(tag, "NOOP completed")

    def cmd_getquota(self, tag, args, uid):
        self.ok(tag, "GETQUOTA completed")    # 无配额 → 空应答本身即合规

    def cmd_getquotaroot(self, tag, args, uid):
        mailbox = _quote(args.split()[0] if args.split() else b"INBOX")
        self.send(b"* QUOTAROOT " + mailbox + b' ""')
        self.ok(tag, "GETQUOTAROOT completed")

    def cmd_create(self, tag, args, uid):
        # CREATE 无强制 untagged 应答；多发 * LIST 只会让客户端缓存出脏数据
        self.ok(tag, "CREATE completed")


class FakeImapServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT)

    def process_request_thread(self, request, client_address):
        """并发上限：超限直接 '* BYE' 关闭，避免线程无限增长（并归还令牌）。"""
        if not self._slots.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.sendall(b"* BYE [ALERT] server too busy\r\n")
            self.close_request(request)
            return
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


# --------------------------------------------------------------- GTK4 界面

try:
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk, GLib
    HAS_GTK = True
except Exception as exc:                       # headless/CI 环境无 GTK 也能跑
    HAS_GTK = False
    GTK_ERR = exc


if HAS_GTK:

    class FakeImapApp(Gtk.Application):
        def __init__(self):
            super().__init__(application_id=APP_ID)      # 默认即 FLAGS_NONE 单实例
            self.server = None
            self.server_thread = None
            self.server_error = None
            self.stats_label = None

        # ---- 服务器生命周期 ----
        def start_server(self):
            try:
                self.server = FakeImapServer((HOST, PORT), FakeImapHandler)
            except OSError as e:
                self.server_error = f"无法监听 {HOST}:{PORT} — {e}"
                print(f"[!] {self.server_error}", file=sys.stderr, flush=True)
                return
            self.server_thread = threading.Thread(
                target=self.server.serve_forever, name="fake-imap", daemon=True)
            self.server_thread.start()
            print(f"[*] listening on {HOST}:{self.port()}", flush=True)

        def port(self):
            return self.server.server_address[1] if self.server else PORT

        def stop_server(self):
            if self.server is not None:
                self.server.shutdown()
                self.server.server_close()
                self.server = None
                print("[*] server stopped", flush=True)

        # ---- GTK ----
        def do_startup(self):
            Gtk.Application.do_startup(self)
            self.start_server()

        def do_activate(self):
            (self.props.active_window or self.build_window()).present()

        def build_window(self):
            win = Gtk.ApplicationWindow(application=self)
            win.set_title(APP_NAME)
            win.set_default_size(380, 200)
            win.set_resizable(False)

            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            for m in ("top", "bottom"):
                getattr(box, f"set_margin_{m}")(26)
            for m in ("start", "end"):
                getattr(box, f"set_margin_{m}")(28)
            box.set_valign(Gtk.Align.CENTER)

            header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            header.set_valign(Gtk.Align.CENTER)
            with contextlib.suppress(Exception):
                icon = Gtk.Image.new_from_icon_name(APP_ID)
                icon.set_pixel_size(40)
                header.append(icon)
            title = Gtk.Label(label=APP_NAME)
            title.add_css_class("title-3")
            header.append(title)
            box.append(header)

            status = Gtk.Label(label=("启动失败" if self.server_error
                                      else f"{APP_NAME} 正在运行"))
            status.add_css_class("title-4")
            if self.server_error:
                status.add_css_class("error")
            box.append(status)

            self.stats_label = Gtk.Label(label=f"监听 127.0.0.1:{self.port()} · 连接 0 · 命令 0")
            self.stats_label.add_css_class("dim-label")
            self.stats_label.set_wrap(True)
            box.append(self.stats_label)

            if self.server_error:
                err = Gtk.Label(label=self.server_error)
                err.add_css_class("caption")
                err.set_wrap(True)
                box.append(err)

            hint = Gtk.Label(label="关闭此窗口即终止进程")
            hint.add_css_class("dim-label")
            hint.add_css_class("caption")
            box.append(hint)

            win.set_child(box)
            win.connect("close-request", lambda *_: (self.quit(), False)[1])
            GLib.timeout_add_seconds(1, lambda: self.tick())
            return win

        def tick(self):
            with _LOCK:
                c, q, kb = STATS["connections"], STATS["commands"], STATS["bytes"] // 1024
            if self.stats_label:
                self.stats_label.set_text(
                    f"监听 127.0.0.1:{self.port()} · 连接 {c} · 命令 {q} · {kb} KiB")
            return GLib.SOURCE_CONTINUE

        def do_shutdown(self):
            self.stop_server()
            Gtk.Application.do_shutdown(self)


# ------------------------------------------------------------------ 入口

def run_headless():
    server = FakeImapServer((HOST, PORT), FakeImapHandler)
    print(f"[*] {APP_NAME} listening on {HOST}:{server.server_address[1]} (headless)",
          flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *a: stop.set())
    signal.signal(signal.SIGTERM, lambda *a: stop.set())
    try:
        while not stop.wait(0.2):
            pass
    finally:
        server.shutdown()
        server.server_close()
        print("[*] stopped", flush=True)


def main(argv):
    global HOST, PORT, HEADLESS
    if "--headless" in argv or "-n" in argv:
        HEADLESS = True
    for i, a in enumerate(argv):
        if a in ("--port", "-p") and i + 1 < len(argv):
            PORT = int(argv[i + 1])
        elif a in ("--host", "-H") and i + 1 < len(argv):
            HOST = argv[i + 1]

    if HEADLESS or not HAS_GTK:
        if not HEADLESS:
            print(f"[!] GTK 不可用（{GTK_ERR}），改为 headless 模式", flush=True)
        run_headless()
        return 0

    app = FakeImapApp()

    def _quit(*_):
        app.quit()
        return GLib.SOURCE_REMOVE

    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, _quit)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, _quit)
    code = app.run([])
    os._exit(code)                # 服务线程为 daemon，这里确保进程立即整体退出


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
