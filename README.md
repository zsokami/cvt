# ACL4SSR Mannix 订阅转换极速版

用于在 Clash(Meta/mihomo)、Clash proxies、base64 和 uri 订阅格式之间进行快速转换，纯 TypeScript 实现，最大化转换速度

emoji、代理策略组和路由规则与 [ACL4SSR_Online_Full_Mannix.ini](https://github.com/zsokami/ACL4SSR) 大致相同，url-test 间隔时间改为随节点数变化，最少 15 秒

||URI|Clash|
|-|:-:|:-:|
|http|✅|✅|
|socks5|✅|✅|
|ss|✅|✅|
|ssr|✅|✅|
|mieru|❌|✅|
|snell|❌|✅|
|vmess|✅|✅|
|vless|✅|✅|
|trojan|✅|✅|
|hysteria|✅|✅|
|hysteria2|✅|✅|
|tuic|✅|✅|
|wireguard|✅|✅|
|ssh|❌|✅|
|anytls|✅|✅|

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
| hide | 无 | 在 proxy-groups 中隐藏指定节点，在 proxies 中仍保留，和 dialer-proxy 配合以隐藏前置节点，使用正则表达式 |

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
deno run -A https://raw.githubusercontent.com/zsokami/cvt/main/scripts/cvt.ts [-o <path>] [<from>] [<to>] [-ua <ua>] [-ndl] [-hide <hide>]
```

参数

- `-o <path>` 输出路径

- `<from>` http/s 订阅链接、除 http/s 代理的 uri、用 base64/base64url 编码的订阅内容或 Data URL，多个用 | 分隔。获取零节点订阅用 empty，可用于去广告

- `<to>` clash、clash-proxies、base64、uri 或 auto(若 ua 含 clash 则 clash 否则 base64)

- `-ua <ua>` User-Agent 请求头

- `-ndl` 无 DNS 泄漏

- `-hide <hide>` 在 proxy-groups 中隐藏指定节点，在 proxies 中仍保留，和 dialer-proxy 配合以隐藏前置节点，使用正则表达式

例子

```sh
deno run -A https://raw.githubusercontent.com/zsokami/cvt/main/scripts/cvt.ts -o clash.yaml 'https://example.com/subscribe?token=xxx'
```
