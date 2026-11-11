# 🌸 SakuNet

**QX 的操作与设计语言 + Surge 配置全兼容：导入一份 Surge 配置即可用。**

个人 Windows 代理客户端，不内置自己的分流体系——**Surge 配置就是配置源**：在设置页导入一份 Surge `.conf`，节点、策略组、分流规则全部由它派生，生成的路由与它逐条对应，SakuNet 不叠加任何自带规则。内核选用 **sing-box ≥ 1.14**：原生覆盖 Snell 4/6（含 v6 的 `default / unshaped / unsafe-raw` 模式——这是选它的决定性理由，mihomo 正式版的 Snell 只到 v5），同时吃下 AnyTLS、Hysteria2、Naive、VLESS、VMess、Trojan、Shadowsocks，一套内核全协议。

界面不发明新交互：**以 Quantumult X 的设计语言为第一参照**（节点行国旗＋彩色延迟胶囊、底部三标签栏、卡片式策略组），操作骨架是 Surge / Shadowrocket 的范式（大开关＋「规则分流 / 全部代理 / 全部直连」三段模式＋策略组点选），换平台零学习成本。

## 配置来源

**主路径：Surge 配置导入（v0.3）**。设置页第一张卡就是导入入口，导入在本机完成、不上传任何内容。迁移口径：

| Surge 段 | 迁移结果 |
|---|---|
| [Proxy] | snell（v4/5/6，含 mode）、anytls、hysteria2、naive、ss（含 obfs→obfs-local 插件）、trojan、vmess、vless（含 Reality）、http/https、socks5 → sing-box 出站 |
| [Proxy Group] | select → selector；url-test / smart / fallback → urltest（smart 无对应物，按最低延迟近似）；load-balance → selector；`include-all-proxies`、`include-other-group`、嵌套组、`policy-regex-filter` 均按语义展开 |
| [Rule] | DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR(6) / SRC-IP / DEST-PORT / PROTOCOL / PROCESS-NAME → 路由规则，排在最前（手写优先）；RULE-SET / DOMAIN-SET 若指向 slynnnn/surge-rules 仓的 lists，映射到该仓 platforms/singbox 的同名规则集；FINAL → route final |
| [MITM] / [URL Rewrite] / [Script] | **解析并完整保存**（存入 imported.json 的 engine 字段），导入结果页单列「已导入 · 引擎待上线」——引擎本体（MITM 代理层＋重写/脚本执行）是 v0.4 第一项；v0.3 只保存、不生效，但一份都不丢 |
| 未迁移 | 外部（非 surge-rules）RULE-SET、USER-AGENT、GEOIP、URL-REGEX、AND/OR 逻辑规则、目标策略不存在的规则——逐条列入导入结果页的「未迁移清单」，不静默丢弃 |

导入结果存为应用目录下的 `imported.json`（权限 0600），设置页「当前生效来源」展示其文件名与导入时间；导入报告（成功计数＋未迁移清单＋近似说明）在设置页随时可回看。

**兜底（未导入任何配置时）**：手填 `nodes.json` 仍可用，此时才启用 SakuNet 的内置默认——内置五组（节点选择 / AI / 流媒体 / 社交 / 漏网之鱼，成员为全部节点）＋ surge-rules 的 merged 六件远程规则集（ads / ai / streaming / social / global / china）做分流。导入 Surge 配置后这套内置默认**完全不生效**，避免双套规则打架。

v0.2 做了「QX × Surge 取长补短」校准（依据为对 QX 1.8.1 / Surge 5.102.0 已解密 IPA 的资源层实测提取）：延迟胶囊保留 Surge 式具体毫秒数字、配色换 QX 的系统色纪律（#34C759 / #FF9500 / #FF3B30）；策略组图标位对齐 QX policy-image 的 36px；选中态在对勾之外吸收 QX 标志性的 4×16 竖条标记；三段文案改 QX 官方口径。底色 #F2F2F7 与连接绿 #34C759 经实测与现值一致，未动。

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
│  · 导入的 Surge 配置（或兜底 nodes.json）      │
│    → 生成 sing-box 配置                        │
│  · 经 Clash API（127.0.0.1:9090）查组/切换/测速 │
│  · 模式切换在应用层做：重生成 route + 重启内核  │
└───────────────┬──────────────────────────────┘
                │ 侧车进程（sing-box run -c …）
┌───────────────▼──────────────────────────────┐
│ sing-box.exe ≥ 1.14                           │
│  · mixed 入站 127.0.0.1:2080（+ 可选 TUN）     │
│  · 规则集仅来自导入配置自己的 RULE-SET 引用，  │
│    经 surge-rules 的 platforms/singbox 映射    │
└──────────────────────────────────────────────┘
```

模式说明：sing-box 的 Clash API 在普通配置下 `mode-list` 只有 `rule`，PATCH 切模式是空操作（实测）——所以「全局代理 / 全局直连」由外壳重写 route 的 final 并重启内核实现，模式持久化在 `sakunet-mode.json`。

规则引导：规则集域名的 DNS 固定走直连（dns-local），节点全挂时规则集也能先拉下来。

## 使用

1. 从 Releases 下载 `SakuNet-windows-amd64.zip`，或按下面自己构建。
2. 运行 `SakuNet.exe`，浏览器打开 http://127.0.0.1:18090 。
3. **第一步**：到「设置」页导入你的 Surge `.conf` 文件，看一眼导入报告（成功计数与未迁移清单）。
4. 回到主页点顶部开关启动内核；需要全局接管时在设置页开「系统代理」（写 HKCU 注册表，指向 127.0.0.1:2080）。
5. 没有 Surge 配置时也可手填 `nodes.json`（见下方字段说明，走内置兜底分流；**nodes.json 已被 .gitignore 排除，永不入库**）。

## 构建

```powershell
# 需要 Go 1.25+
.\fetch-core.ps1                 # 下载 sing-box 1.14.4 + libcronet.dll 到当前目录
go build -o SakuNet.exe .        # CGO_ENABLED=0，纯静态
go test ./...                    # 配置生成单测（模式/Snell 映射/Surge 导入）
.\SakuNet.exe genconfig nodes.json out.json   # 只生成 sing-box 配置（调试用）
.\SakuNet.exe surge2json Surge.conf [out.json] # 离线把 Surge 配置转成 sing-box 配置并打印迁移报告；省略 out.json 时只在内存里解析计数、不写任何文件
```

## nodes.json 字段（兜底路径）

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

- v0.2（已发布）：QX × Surge 校准——延迟胶囊系统色、组图标 36px、选中竖条＋对勾、三段文案改 QX 口径（规则分流 / 全部代理 / 全部直连）、次级文字 #3C3C43 α60% 一档、按钮高度归一 30px 档
- v0.3（本版）：Surge 配置导入成为主配置源——节点/策略组/分流规则全部由导入配置派生、不叠加内置规则；[MITM]/[URL Rewrite]/[Script] 解析保存待引擎；nodes.json 降为兜底；首启引导改为「先导入 Surge 配置」
- v0.4：**MITM＋URL Rewrite 引擎**（消费 v0.3 已保存的 engine 数据，含 Script 执行）、系统托盘、TUN 开关打磨、订阅 URL 导入（snell:// / anytls:// 等链接解析）

## 许可

MIT。内核 sing-box 为其自身许可（GPLv3），以独立进程（侧车）方式分发、未静态链接进本程序。
