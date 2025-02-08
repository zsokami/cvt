import { cvt } from '../netlify/edge-functions/main/cvt.ts'

const oidx = Deno.args.indexOf('-o')
let out_path = ''
if (~oidx) {
  out_path = Deno.args[oidx + 1]
  Deno.args.splice(oidx, 2)
}

if (!Deno.args.length) {
  console.log(`用于在 Clash(Meta/mihomo)、Clash proxies、base64 和 uri 订阅格式之间进行快速转换

deno run -A cvt.ts [-o <path>] [<from>] [<to>] [<ua>]
  -o <path>
  输出路径

  <from>
  http/s 订阅链接、除 http/s 代理的 uri、用 base64/base64url 编码的订阅内容或 Data URL, 多个用 | 分隔
  获取零节点订阅用 empty, 可用于去广告

  <to>
  clash、clash-proxies、base64、uri 或 auto(若 ua 含 clash 则 clash 否则 base64)

  <ua>
  User-Agent 请求头`)
  Deno.exit()
}

const [result, counts, headers] = await cvt(Deno.args[0], Deno.args[1], Deno.args[2])

if (out_path) {
  Deno.writeTextFileSync(out_path, result)
} else {
  console.log(result)
}

if (headers?.has('subscription-userinfo')) {
  console.log(`订阅信息: ${headers.get('subscription-userinfo')}`)
}
console.log(`总节点: ${counts[2]}, 成功转换节点: ${counts[1]}, 过滤后节点: ${counts[0]}`)
