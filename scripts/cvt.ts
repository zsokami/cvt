import { cvt } from '../netlify/edge-functions/main/cvt.ts'
import { parseBool } from '../netlify/edge-functions/main/utils.ts'

let out_path, ua, ndl, filter, hide, meta

const args = []

for (let i = 0; i < Deno.args.length; i++) {
  const arg = Deno.args[i]
  switch (arg) {
    case '-o':
      out_path = Deno.args[++i]
      break
    case '-ua':
      ua = Deno.args[++i]
      break
    case '-ndl':
      ndl = true
      break
    case '-filter':
      filter = Deno.args[++i]
      break
    case '-hide':
      hide = Deno.args[++i]
      break
    case '-meta':
      meta = parseBool(Deno.args[++i])
      break
    default:
      args.push(arg)
  }
}

if (!args.length) {
  console.log(`用于在 Clash(Meta/mihomo)、Clash proxies、base64 和 uri 订阅格式之间进行快速转换

deno run -A cvt.ts [-o <path>] [<from>] [<to>] [-ua <ua>] [-ndl] [-filter <filter>] [-hide <hide>]
  -o <path>
  输出路径

  <from>
  http/s 订阅链接、除 http/s 代理的 uri、用 base64/base64url 编码的订阅内容或 Data URL, 多个用 | 分隔
  获取零节点订阅用 empty, 可用于去广告

  <to>
  clash、clash-proxies、base64、uri 或 auto(若 ua 含 clash 则 clash 否则 base64)

  -ua <ua>
  User-Agent 请求头

  -ndl
  无 DNS 泄漏

  -filter <filter>
  筛选节点, 见 https://github.com/zsokami/cvt#筛选语法

  -hide <hide>
  在 proxy-groups 中隐藏指定节点, 在 proxies 中仍保留, 和 dialer-proxy 配合以隐藏前置节点, 见 https://github.com/zsokami/cvt#筛选语法

  -meta <0|1>
  设置为 0 去除仅 Meta/mihomo 内核支持的节点/策略, 以兼容原版 Clash, 设置为 1 则强制包含 Meta/mihomo 功能, 默认从 User-Agent 中判断`)
  Deno.exit()
}

const [result, counts, headers] = await cvt(args[0], args[1], { ua, ndl, filter, hide, meta })

if (out_path) {
  Deno.writeTextFileSync(out_path, result)
} else {
  console.log(result)
}

if (headers?.has('subscription-userinfo')) {
  console.log(`订阅信息: ${headers.get('subscription-userinfo')}`)
}
console.log(`总节点: ${counts[2]}, 成功转换节点: ${counts[1]}, 过滤后节点: ${counts[0]}`)
