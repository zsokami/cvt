# ACL4SSR Mannix 订阅转换极速版

用于在 Clash(Meta/mihomo)、Clash proxies、base64 和 uri 订阅格式之间进行快速转换，纯 TypeScript 实现，最大化转换速度

emoji、代理策略组和路由规则与 [ACL4SSR_Online_Full_Mannix.ini](https://github.com/zsokami/ACL4SSR) 大致相同，url-test 间隔时间改为随节点数变化，最少 15 秒

||URI|Clash|
|-|:-:|:-:|
|http|✔️|✔️|
|socks5|✔️|✔️|
|ss|✔️|✔️|
|ssr|✔️|✔️|
|mieru|❌|✔️|
|snell|❌|✔️|
|vmess|✔️|✔️|
|vless|✔️|✔️|
|trojan|✔️|✔️|
|hysteria|✔️|✔️|
|hysteria2|✔️|✔️|
|tuic|✔️|✔️|
|wireguard|✔️|✔️|
|ssh|❌|✔️|
|anytls|✔️|✔️|
|sudoku|❌|✔️|

## 远程转换

[配套 Web 前端](https://github.com/zsokami/scweb)

用法

```
https://arx.cc[/!<args>]/<from>
```

`<args>`

参数列表，格式：`key=value&key2=value2...`

| 参数 | 默认 | 说明 |
| - | - | - |
| to | clash | 目标订阅格式，支持 clash、clash-proxies、base64、uri 或 auto(Clash 客户端则 clash 否则 base64)，该参数可省略 `to=` 前缀 |
| ua | 无 | 覆盖 User-Agent 请求头 |
| filename | 无 | 覆盖文件名 |
| ndl | 无 | 存在该参数则返回无 DNS 泄漏(No_DNS_Leak)配置 |
| filter | 无 | 筛选节点，见 [筛选语法](#筛选语法) |
| hide | 无 | 在 proxy-groups 中隐藏指定节点，在 proxies 中仍保留，和 dialer-proxy 配合以隐藏前置节点，见 [筛选语法](#筛选语法) |
| meta | 从 User-Agent 中判断 | 设置为 0 去除仅 Meta/mihomo 内核支持的节点/策略，以兼容原版 Clash，设置为 1 则强制包含 Meta/mihomo 功能 |

`<from>`

http/s 订阅链接、用 base64/base64url 编码的订阅内容或 Data URL

可以是除 http/s 代理的 uri，但需 URL 编码

多个先用 | 分隔，然后再 URL 编码

获取零节点订阅用 empty，可用于去广告

例子

```
https://arx.cc/https://example.com/subscribe?token=xxx
```
```
https://arx.cc/!auto&ndl/https://example.com/subscribe?token=xxx
```

### 筛选语法

基本条件语法：`[[<字段>] <匹配运算符>] <正则表达式>`

字段、运算符、正则表达式之间的空格会被忽略

<字段>

要匹配的节点字段，可使用 `.` 和 `[]` 表示字段路径，如

- `name`（省略字段默认为 `name`）
- `type`
- `plugin-opts.tls`
- `alpn[0]`
- `$`（表示所有字段）

若字段为对象或数组，则有任一子孙字段匹配即条件成立

<匹配运算符>

- `:` 表示部分匹配，且忽略大小写，对应否定运算符：`!:` 或 `!`
- `=` 表示完整匹配，且区分大小写，对应否定运算符：`!=`

省略字段和运算符默认为 `name:`

可使用 `and`、`or`、`not` 和括号 `()` 组合多个条件

例子

- `CN`、`name:CN` 名称**包含** CN 的节点，**忽略**大小写
- `=CN`、`name=CN` 名称**为** CN 的节点，**区分**大小写
- `^CN$` 名称**为** CN 的节点，**忽略**大小写
- `=.*CN.*` 名称**包含** CN 的节点，**区分**大小写
- `not CN`、`not name:CN`、`!:CN`、`name!:CN` 名称**不**包含 CN 的节点，忽略大小写
- `^(🇭🇰|🇸🇬)` 名称开头为 🇭🇰 或 🇸🇬 的节点
- `type=ss` 类型为 ss 的节点
- `ws-opts.headers.Host:^hk` WS Host 开头为 hk 的节点
- `reality-opts:.*` 使用了 Reality 的节点
- `alpn=h3` alpn 中包含 h3 的节点
- `中转 and type=ss` 名称包含 “中转” 且类型为 ss 的节点

### Serverless / Edge 部署

#### Cloudflare Workers

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zsokami/cvt)

Demo: `https://c.arx.cc/`

#### Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/zsokami/cvt)

Demo: `https://v.arx.cc/`

#### Netlify

[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/zsokami/cvt)

Demo: `https://arx.cc/`

#### Deno Deploy

[![Deploy on Deno](https://deno.com/button)](https://console.deno.com/new?clone=https://github.com/zsokami/cvt)

Demo: `https://d.arx.cc/`

#### Koyeb

[![Deploy to Koyeb](https://www.koyeb.com/static/images/deploy/button.svg)](https://app.koyeb.com/deploy?type=git&name=cvt&repository=zsokami%2Fcvt&branch=main&builder=dockerfile&instance_type=free&ports=8000%3Bhttp2%3B%2F)

Demo: `https://cvt.koyeb.app/`

## 本地转换

### 本地服务

需先安装 [Deno](https://deno.com/)

运行

```sh
deno run -A https://raw.githubusercontent.com/zsokami/cvt/main/main.ts
```

指定端口

```sh
deno run -A https://raw.githubusercontent.com/zsokami/cvt/main/main.ts 8000
```

指定主机名/IP:端口

```sh
deno run -A https://raw.githubusercontent.com/zsokami/cvt/main/main.ts [::1]:8000
```

更新版本并运行

```sh
deno run -A -r https://raw.githubusercontent.com/zsokami/cvt/main/main.ts
```

查看版本

```
http://127.0.0.1:8000/version
```

### 命令行

需先安装 [Deno](https://deno.com/)

用法

```sh
deno run -A https://raw.githubusercontent.com/zsokami/cvt/main/scripts/cvt.ts [-o <path>] [<from>] [<to>] [-ua <ua>] [-ndl] [-filter <filter>] [-hide <hide>] [-meta <0|1>]
```

参数

- `-o <path>` 输出路径

- `<from>` http/s 订阅链接、除 http/s 代理的 uri、用 base64/base64url 编码的订阅内容或 Data URL，多个用 | 分隔。获取零节点订阅用 empty，可用于去广告

- `<to>` clash、clash-proxies、base64、uri 或 auto(若 ua 含 clash 则 clash 否则 base64)

- `-ua <ua>` User-Agent 请求头

- `-ndl` 无 DNS 泄漏

- `-filter <filter>` 筛选节点，见 [筛选语法](#筛选语法)

- `-hide <hide>` 在 proxy-groups 中隐藏指定节点，在 proxies 中仍保留，和 dialer-proxy 配合以隐藏前置节点，见 [筛选语法](#筛选语法)

- `-meta <0|1>` 设置为 0 去除仅 Meta/mihomo 内核支持的节点/策略，以兼容原版 Clash，设置为 1 则强制包含 Meta/mihomo 功能，默认从 User-Agent 中判断

例子

```sh
deno run -A https://raw.githubusercontent.com/zsokami/cvt/main/scripts/cvt.ts -o clash.yaml 'https://example.com/subscribe?token=xxx'
```
