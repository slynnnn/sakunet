# 🌸 SakuNet

个人 Windows 代理客户端：为「协议很杂」的自用节点而做——尤其是 **Snell v6**。

市面客户端的内核大多是 mihomo，而 mihomo 正式版只支持 Snell v1–v5（v6 还在 alpha）。SakuNet 选用 **sing-box ≥ 1.14** 作内核：它原生覆盖 Snell 4/6（含 v6 的 `default / unshaped / unsafe-raw` 流量整形模式），同时吃下 AnyTLS、Hysteria2、Naive、TUIC、VLESS、VMess、Trojan、Shadowsocks，一套内核全协议。

界面不发明新交互：**以 Quantumult X 的设计语言为第一参照**（节点行国旗＋彩色延迟胶囊、底部三标签栏、卡片式策略组），操作骨架是 Surge / Shadowrocket 的范式（大开关＋「规则 / 全局代理 / 全局直连」三段模式＋策略组点选），换平台零学习成本。

## 协议矩阵

| 协议 | 支持 | 说明 |
|---|---|---|
| Snell v6 | ✅ | sing-box 1.14 新增；mode 三档（default/unshaped/unsafe-raw）；PSK 须 12–255 字节 |
| Snell v5 | ✅ | v5 的 TCP 线协议与 v4 相同（v5 只多 QUIC Proxy Mode，未实现），故以 version=4 发出 |
| AnyTLS | ✅ | |
| Hysteria2 | ✅ | 含 salamander obfs |
| Naive | ✅ | 依赖内核包里的 libcronet.dll，fetch-core 会一并放好 |
| VLESS / VMess / Trojan / Shadowsocks（含 2022） | ✅ | VLESS 支持 Reality + xtls-rprx-vision |
| TUIC 等 sing-box 其余协议 | ⏳ | 内核支持，nodes.json 建模在路线图上 |

为什么不用 mihomo：正式版 Snell 只到 v5，v6 在 alpha 分支；用户的在用节点是 v6，没得选。

## 架构

```
┌──────────────────────────────────────────────┐
│ SakuNet.exe（Go 外壳）                        │
│  · 本地 Web 面板 http://127.0.0.1:18090       │
│  · nodes.json → 生成 sing-box 配置            │
│  · 经 Clash API（127.0.0.1:9090）查组/切换/测速 │
│  · 模式切换在应用层做：重生成 route + 重启内核  │
└───────────────┬──────────────────────────────┘
                │ 侧车进程（sing-box run -c …）
┌───────────────▼──────────────────────────────┐
│ sing-box.exe ≥ 1.14                           │
│  · mixed 入站 127.0.0.1:2080（+ 可选 TUN）     │
│  · 远程规则集 ← slynnnn/surge-rules           │
│    platforms/singbox/*.json（每日更新）        │
└──────────────────────────────────────────────┘
```

模式说明：sing-box 的 Clash API 在普通配置下 `mode-list` 只有 `rule`，PATCH 切模式是空操作（实测）——所以「全局代理 / 全局直连」由外壳重写 route 的 final 并重启内核实现，模式持久化在 `sakunet-mode.json`。

规则引导：规则集域名的 DNS 固定走直连（dns-local），节点全挂时规则集也能先拉下来。

## 使用

1. 从 Releases/Actions 下载 `SakuNet-windows-amd64.zip`，或按下面自己构建。
2. 把 `nodes.example.json` 复制为 `nodes.json`，填入自己的节点（**nodes.json 已被 .gitignore 排除，永不入库**）。
3. 运行 `SakuNet.exe`，浏览器打开 http://127.0.0.1:18090 ，点顶部开关启动内核。
4. 需要全局接管时在设置页开「系统代理」（写 HKCU 注册表，指向 127.0.0.1:2080）。

## 构建

```powershell
# 需要 Go 1.25+
.\fetch-core.ps1                 # 下载 sing-box 1.14.4 + libcronet.dll 到当前目录
go build -o SakuNet.exe .        # CGO_ENABLED=0，纯静态
go test ./...                    # 配置生成单测（模式/Snell 映射）
.\SakuNet.exe genconfig nodes.json out.json   # 只生成 sing-box 配置（调试用）
```

## nodes.json 字段

必填：`name / type / server / port`。按协议选填：

- snell：`psk`、`version`（5 或 6）、`mode`（v6：default/unshaped/unsafe-raw）、`tfo`
- anytls / trojan：`password`、`sni`、`insecure`
- hysteria2：`password`、`sni`、`obfs_password`（可选）
- naive：`username`、`password`、`sni`
- vless：`uuid`、`flow`、`sni`、`reality_public_key`、`reality_short_id`
- vmess：`uuid`、`alter_id`、`security`、`sni`
- shadowsocks：`method`、`password`（2022 方法的 password 是 base64 密钥）
- 顶层 `tun: true` 可开启 TUN 入站（需管理员权限运行）

## 路线图

- v0.2：系统托盘、TUN 开关打磨、订阅 URL 导入（snell:// / anytls:// 等链接解析）
- v0.3：直接导入 slynnnn/surge-config 私有仓的 Surge 配置（节点与分流口径自动迁移）

## 许可

MIT。内核 sing-box 为其自身许可（GPLv3），以独立进程（侧车）方式分发、未静态链接进本程序。
