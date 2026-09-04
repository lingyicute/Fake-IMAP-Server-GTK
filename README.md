# Fake IMAP Server

接受**任意** IMAP 请求并进行**空应答**的假 IMAP 服务；运行时弹出 GTK4 小窗口显示
“Fake IMAP Server 正在运行”，**关闭窗口即终止进程**。以 Flatpak 打包。

```
.
├── src/fake_imap_server.py                      # 协议层 + GTK4 界面
├── tests/smoke_test.py                          # RFC 3501/9051 语法一致性冒烟测试
├── data/
│   ├── io.github.fakeimap.FakeImapServer.svg            # 圆角矩形图标
│   ├── io.github.fakeimap.FakeImapServer.desktop        # 桌面入口
│   └── io.github.fakeimap.FakeImapServer.metainfo.xml   # AppStream 元信息
├── io.github.fakeimap.FakeImapServer.yml        # Flatpak 清单
└── .github/workflows/build.yml                  # CI：先跑协议测试，再 flatpak-builder 打包
```

## 协议合规性

默认行为是“空应答”，但**空应答也必须满足 ABNF**，否则客户端解析器会直接报错或永久挂起。

| 场景 | 应答 | 依据 |
|---|---|---|
| 建立连接 | `* OK [CAPABILITY IMAP4rev1 LITERAL+ ENABLE IDLE NAMESPACE UNSELECT ID] Fake IMAP Server ready` | §6.1.1 / §7.2.1 |
| 无强制 untagged 数据的任意命令（`CREATE`、`STORE`、`RENAME`、`LISTRIGHTS`…） | `<tag> OK <cmd> completed` | `resp-text = ["[" resp-code "]" SP] text`，**text 必填**，绝不发裸 `A1 OK` |
| `CAPABILITY` | `* CAPABILITY …` + `OK` | §7.2.1 |
| `SELECT` / `EXAMINE` | `* 0 EXISTS`、`* 0 RECENT`、`* FLAGS (…)`、`* OK [PERMANENTFLAGS …]`、`* OK [UIDVALIDITY 1]`、`* OK [UIDNEXT 1]`、`OK [READ-WRITE]`/`[READ-ONLY]` | §6.3.1 进入 selected 状态的硬性要求 |
| `LIST "" ""` / `LIST "" "*"` | `* LIST (\Noselect) "/" ""` | §6.3.8 根查询必须给出分隔符 |
| `SEARCH` / `SORT` / `THREAD` | `* SEARCH` / `* SORT` / `* THREAD`（空结果也要有该行） | §6.4.4 / RFC 5256 |
| `STATUS` | `* STATUS "INBOX" (MESSAGES 0 UNSEEN 0 UIDNEXT 1 UIDVALIDITY 1 HIGHESTMODSEQ 0)` | §6.3.6 |
| `NAMESPACE` | `* NAMESPACE (("" "/")) NIL NIL` | RFC 2342 |
| `MYRIGHTS` | `* MYRIGHTS "INBOX" "lksatwen"` | RFC 4314 |
| `ENABLE` | `* ENABLED`（**不是** `* ENABLE`） | RFC 5161 |
| `ID` | `* NIL ("name" "Fake IMAP Server" …)` | RFC 2971 |
| 同步字面量 `{n}` | 先 `+ go ahead`，吞掉 n 字节，**续行拼回原命令**，tag 不丢失 | §4.3 / §7.5 |
| 非同步字面量 `{n+}` | 不继续索要数据（LITERAL+） | RFC 3516 |
| `IDLE` | 先 `+ idling`，收到 `DONE` 后才发完成应答 | RFC 2177 |
| `LOGOUT` | `* BYE …` + `<tag> OK` 后关闭 | §6.1.2 / §7.1.5 |
| 非法 tag（含 `+`）/ 缺命令名 | `<tag> BAD malformed tag`、`* BAD …`（保持连接可用） | §2.2.1 “SHOULD strictly enforce” |
| `FETCH` / `STORE` / `COPY` | `<tag> NO no messages exist` | 空邮箱（EXISTS=0）下唯一合规应答，不伪造条目 |
| `AUTHENTICATE` | `<tag> NO no supported SASL mechanisms offered` | 直接回 OK 会让客户端苦等挑战数据 |
| `STARTTLS` / `COMPRESS` | `<tag> BAD`（未声明的能力不受理） | 不谎报 capability |

**有意的取舍**：不实现真实消息存储，因此 `EXISTS` 恒为 0、`APPEND` 接收后即丢弃、
`SEARCH` 恒为空。默认不强制状态机（未登录也能 `SELECT`），需要严格行为时设
`FAKE_IMAP_ENFORCE_STATE=1`。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `FAKE_IMAP_HOST` | `127.0.0.1` | 监听地址（改成 `0.0.0.0` 可对外） |
| `FAKE_IMAP_PORT` | `1143` | 监听端口，`0` 为随机端口 |
| `FAKE_IMAP_HEADLESS` | – | `1` 不建窗口，纯服务（CI/服务器用） |
| `FAKE_IMAP_FOLDERS` | 空 | 逗号分隔邮箱名，如 `INBOX,Sent,Drafts,Trash` |
| `FAKE_IMAP_ENFORCE_STATE` | – | `1` 严格按未认证/已认证/已选择状态校验命令 |
| `FAKE_IMAP_READ_TIMEOUT` | `1800` | 命令间空闲秒数，超时回 `* BYE` 并断开 |
| `FAKE_IMAP_IDLE_TIMEOUT` | `1800` | `IDLE` 最长保持秒数 |

## 构建 / 运行

```bash
flatpak install flathub org.gnome.Platform//47 org.gnome.Sdk//47
flatpak-builder --user --install --force-clean build-dir io.github.fakeimap.FakeImapServer.yml
flatpak run io.github.fakeimap.FakeImapServer
flatpak run --env=FAKE_IMAP_PORT=143 --env=FAKE_IMAP_FOLDERS=INBOX,Sent io.github.fakeimap.FakeImapServer
```

不打包直接跑（需 GTK4 + PyGObject）：

```bash
python3 src/fake_imap_server.py            # 带窗口
python3 src/fake_imap_server.py --headless --port 1143
```

## 测试

```bash
python3 tests/smoke_test.py                # 40+ 项 ABNF / untagged 应答校验
```

手工验证：

```
$ nc 127.0.0.1 1143
* OK [CAPABILITY IMAP4rev1 LITERAL+ ENABLE IDLE NAMESPACE UNSELECT ID] Fake IMAP Server ready
a1 LIST "" ""
* LIST (\Noselect) "/" ""
a1 OK LIST completed
a2 LOGIN u p
a2 OK [CAPABILITY IMAP4rev1 LITERAL+ ENABLE IDLE NAMESPACE UNSELECT ID] LOGIN completed
a3 IDLE
+ idling
DONE
a3 OK IDLE completed
a4 LOGOUT
* BYE Fake IMAP Server signing off
a4 OK LOGOUT completed
```

## Flatpak 说明

* `finish-args` 里必须 `--share=network`，否则沙箱内无法 bind 端口；
* 图标/桌面入口/metainfo 使用与 `app-id` 完全一致的文件名，否则 GNOME 无法关联窗口与图标；
* 应用以单实例（`G_APPLICATION_FLAGS_NONE`）运行，二次启动只会把已有窗口提到前台；
* 服务线程为 daemon 线程，`activate` 退出时显式 `os._exit()`，保证关窗即终止进程。
