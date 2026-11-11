# 🌸 SakuNet

**QX 的操作与设计语言 + Surge 配置全兼容：导入一份 Surge 配置即可用。**

个人 Windows 代理客户端，不内置自己的分流体系——**Surge 配置就是配置源**：在设置页导入一份 Surge `.conf`，节点、策略组、分流规则、MITM 与 URL 重写全部由它派生，SakuNet 不叠加任何自带规则。内核选用 **sing-box ≥ 1.14**：原生覆盖 Snell 4/6（含 v6 的 `default / unshaped / unsafe-raw` 模式——这是选它的决定性理由，mihomo 正式版的 Snell 只到 v5），同时吃下 AnyTLS、Hysteria2、Naive、VLESS、VMess、Trojan、Shadowsocks，一套内核全协议。MITM/重写由自研 Go 引擎层承担（sing-box 没有这层），只解密导入配置 [MITM] 名单内的主机，其余 HTTPS 原样透传。

界面不发明新交互：**以 Quantumult X 的设计语言为第一参照**（节点行国旗＋彩色延迟胶囊、底部标签栏、卡片式策略组），操作骨架是 Surge / Shadowrocket 的范式（大开关＋「规则分流 / 全部代理 / 全部直连」三段模式＋策略组点选），换平台零学习成本。设计参数不是凭印象抄的：对 QX 1.8.1 / Surge 5.102.0 已解密 IPA 做过资源层实测提取（系统色值、36px 策略图标位、选中竖条标记等均有出处）。

## 界面

![主页：状态卡与策略组列表](docs/screenshots/home.png)

主页：状态卡（开关、三段模式、上下行速率）与策略组列表，点行即切换，延迟胶囊按系统色分档。

![活动记录](docs/screenshots/activity.png)

活动记录页：当前连接的目标主机、命中的规则、出口与流量（读内核 connections，如实呈现）。

![节点页](docs/screenshots/nodes.png)

节点页：全部节点平铺＋一键全部测速。

![设置页：导入与引擎](docs/screenshots/settings.png)

设置页：Surge 配置导入、分享链接/订阅导入、模块导入、MITM 引擎与 CA 状态、一键自检与诊断包导出都在这里。

## 能力矩阵（v1.0 最终版）

| 能力 | 状态 | 说明 |
|---|---|---|
| Surge [Proxy] 节点导入 | ✅ 已实现 | snell（v4/5/6，含 mode）、anytls、hysteria2、naive、ss（含 obfs 插件）、trojan、vmess、vless（含 Reality）、http/https、socks5 |
| Surge [Proxy Group] | ✅ 已实现 | select→selector；url-test/fallback→urltest；嵌套组/include/regex 筛选按语义展开 |
| 组 smart / load-balance | ⚠️ 近似 | smart→urltest（最低延迟）；load-balance→selector（sing-box 无对应物，导入报告注明） |
| Surge [Rule] | ✅ 已实现 | DOMAIN 系 / IP-CIDR / SRC-IP / DEST-PORT / PROTOCOL / PROCESS-NAME；RULE-SET 指向 surge-rules 仓时映射到 sing-box 格式 |
| 外部 RULE-SET、USER-AGENT、GEOIP、URL-REGEX、逻辑复合规则 | ❌ 不支持 | 平台无对应物，逐条列入「未迁移清单」，不静默丢弃 |
| MITM 引擎 | ✅ 已实现 | 仅 [MITM] hostname 命中才解密；CA 用导入配置里已有的 p12（本机内存解码）；面板可下载 CA 证书并给出 Windows 安装指引 |
| URL Rewrite 引擎 | ✅ 已实现 | 302/307 重定向、reject 类（reject/reject-200/-img/-dict/-array）、header 类（请求头/响应头的 set/add/del，语法见引擎说明）；其余类型逐条标「不支持」并在设置页列出 |
| 模块 .sgmodule | ✅ 已实现（部分） | 内嵌 MITM hostname 与重写规则并入引擎生效；脚本部分**不执行**（见下行），含脚本的模块导入时明确标注 |
| Surge/QX 的 JS 脚本引擎 | ❌ 不含 | 不实现 JavaScriptCore 式脚本运行时；用户在用的真实配置无 [Script] 条目，[Script] 定义仅保存 |
| 分享链接导入 | ✅ 已实现 | snell://、anytls://、hysteria2://（hy2://）、ss://（含 SIP002/老式）、trojan://、vmess://、vless:// 单链接与订阅 URL（整包 base64 自动识别） |
| TUN 模式 | ✅ 已实现 | 设置页开关；Windows 需管理员，设置页有一键 UAC 提权重启 |
| 系统托盘 | ✅ 已实现（Windows） | 开关内核、模式三段、打开面板、退出 |
| 系统代理 | ✅ 已实现（Windows） | 写 HKCU 注册表；MITM 引擎运行时自动指向引擎层 |
| 活动记录 | ✅ 已实现 | 目标主机 / 规则命中 / 出口链 / 流量 / 起始时间 |
| 一键自检 | ✅ 已实现 | 内核、面板通信、DNS、经当前出口真实请求、规则集状态、MITM/CA、系统代理指向，逐项真跑、人话结论＋处置提示 |
| 导出诊断包 | ✅ 已实现 | 版本、状态、配置结构摘要、自检结果、最近日志；**导出前自动脱敏**（脱敏清单与单测在 internal/diag） |

**最终版明确不含**：JS 脚本引擎（理由如上）、TUIC 等未建模协议的导入（内核支持、导入器未建模）、QX 的规则/脚本生态商店类功能。

## 配置来源

**主路径：Surge 配置导入**。设置页第一张卡就是导入入口，导入在本机完成、不上传任何内容。导入结果存为应用目录下的 `imported.json`（权限 0600），设置页可回看导入报告（成功计数＋未迁移清单＋近似说明）。循环引用组、畸形行等对抗输入在解析层处理：不崩溃，逐条进报告。

**兜底（未导入任何配置时）**：手填 `nodes.json`，此时才启用内置默认五组（节点选择 / AI / 流媒体 / 社交 / 漏网之鱼）＋ surge-rules 的 merged 六件远程规则集。导入 Surge 配置后内置默认完全不生效。

## 架构

```
浏览器/系统代理/TUN
        │
┌───────▼───────────────────────────────────────┐
│ MITM/重写引擎（Go，127.0.0.1:2081，仅引擎启用时） │
│  · [MITM] 名单内 HTTPS：解密 → 重写 → 转内核    │
│  · 其余流量：CONNECT 盲隧道，原样透传            │
└───────┬───────────────────────────────────────┘
        │ CONNECT 链
┌───────▼───────────────────────────────────────┐
│ sing-box 侧车（127.0.0.1:2080 mixed / :9090 API）│
│  · 出站与路由完全由导入的 Surge 配置生成         │
└───────────────────────────────────────────────┘
SakuNet.exe（Go 外壳）：面板 127.0.0.1:18090（仅本机）、
托盘、配置生成、模式切换（应用层重生成 route＋重启内核）、自检/诊断
```

所有监听（面板 18090、mixed 2080、MITM 2081、Clash API 9090）只绑 127.0.0.1，不对外。详见 [SECURITY.md](SECURITY.md)。

## 使用

1. 从 [Releases](https://github.com/slynnnn/sakunet/releases) 下载 `SakuNet-windows-amd64.zip`，解压运行 `SakuNet.exe`（或点托盘图标打开面板），浏览器访问 http://127.0.0.1:18090 。
2. 到「设置」页导入你的 Surge `.conf`，看一眼导入报告。
3. 主页点开关启动；在设置页按需开「系统代理」或「TUN」（TUN 先点「以管理员重启」）。
4. 用了 MITM 的话，把 CA 证书装进 Windows 信任库（设置页 MITM 卡里下载 .cer，有图文步骤）。
5. **日常只需正常使用。出问题先点设置页「一键自检」；看不懂，把「诊断包」下载下来发回来即可**——包里是脱敏过的版本/配置摘要/自检结果/日志，不含节点地址与密码，你不需要描述任何技术细节。

## 验收

- 单元与实测（本机 Linux 构建全跑）：配置生成与 Snell 映射、Surge 导入（含畸形输入对抗集：截断/乱码/重复段/循环引用组不崩溃）、链接解析 7 协议、MITM 引擎真 curl 端到端（302 命中、header 改写在源站可见、非名单主机透传且证书验证走源站 CA）、诊断包脱敏断言（假凭据零出现）。
- sing-box check：导入配置（普通＋TUN 变体）与兜底配置均经 sing-box 1.14.4 `check` 通过。
- 监听面实查：起服后 `ss` 核对四个端口全部 127.0.0.1。
- **真 Windows 自动实测（CI）**：GitHub Actions 的 windows-latest 作业在每次发布时真跑——解压产物、启动 SakuNet.exe、导入演示配置、断言状态/分组接口与内核进程、抓面板截图存档。作业不过，版本不发。（见仓库 workflow 的 windows-smoke 作业。）
- Windows 交叉编译（CGO_ENABLED=0）＋ `go vet` 双目标（linux/windows）通过。

## 构建

```powershell
.\fetch-core.ps1                 # 下载 sing-box 1.14.4 + libcronet.dll
go build -o SakuNet.exe .        # 需要 Go 1.25+，CGO_ENABLED=0 纯静态
go test ./...
.\SakuNet.exe genconfig nodes.json out.json    # 只生成配置（调试）
.\SakuNet.exe surge2json Surge.conf [out.json] # 离线转换＋迁移报告；省略 out 只计数不落盘
```

## nodes.json 字段（兜底路径）

必填 `name / type / server / port`；snell：`psk`、`version`（5 或 6）、`mode`；anytls/trojan：`password`、`sni`、`insecure`；hysteria2：`password`、`obfs_password`；naive：`username`、`password`；vless：`uuid`、`flow`、`reality_public_key`、`reality_short_id`；vmess：`uuid`、`alter_id`、`security`；shadowsocks：`method`、`password`。**nodes.json 已被 .gitignore 排除，永不入库。**

## 版本沿革

- v0.1：外壳＋全协议节点＋QX 风面板
- v0.2：QX × Surge 设计校准（IPA 资源层实测）
- v0.3：Surge 配置导入成为主配置源（配置驱动）
- **v1.0（最终版）**：MITM＋URL Rewrite 引擎、模块并入、TUN、托盘、链接/订阅导入、活动记录、一键自检＋脱敏诊断包、对抗自查与 CI 真 Windows 实测

## 许可

MIT。内核 sing-box 为其自身许可（GPLv3），以独立进程（侧车）方式分发、未静态链接进本程序。
