import { fromURIs, toURIs } from './uris.ts'
import { fromClash, toClash } from './clash.ts'
import { decodeBase64Url, encodeBase64 } from './utils.ts'
import { Proxy } from './types.ts'

import { RE_EMOJI, RE_EMOJI_CN, RE_EMOJI_INFO, RE_EMOJI_SINGLE, RE_EXCLUDE } from './consts.ts'

function from(input: string): [Proxy[], number] {
  // console.time('decodeBase64Url')
  try {
    input = decodeBase64Url(input)
  } catch {
    // pass
  }
  // console.timeEnd('decodeBase64Url')
  // console.time('fromURIs')
  let [proxies, total] = fromURIs(input)
  // console.timeEnd('fromURIs')
  if (total === 0) {
    // console.time('fromClash')
    ;[proxies, total] = fromClash(input)
    // console.timeEnd('fromClash')
  }
  return [proxies, total]
}

function to(proxies: Proxy[], target: string = 'clash'): string {
  switch (target) {
    case 'clash':
      return toClash(proxies)
    case 'clash-proxies':
      return toClash(proxies, true)
    case 'uri':
      return toURIs(proxies)
    case 'base64':
      return encodeBase64(toURIs(proxies))
  }
  throw new Error(`Unknown target: ${target}`)
}

function filter(proxies: Proxy[]): Proxy[] {
  return proxies.filter((x) => !RE_EXCLUDE.test(x.name))
}

function handleEmoji(name: string): string {
  const flags = name.match(/[🇦-🇿]{2}/ug)
  if (flags?.some((flag) => flag !== '🇨🇳')) return name

  const arr: [number, string][] = []
  for (const [flag, zh] of RE_EMOJI) {
    if (!flags || flag === '🇭🇰' || flag === '🇹🇼' || flag === '🇲🇴') {
      for (const m of name.matchAll(zh)) {
        arr.push([m.index + m[0].length, flag])
      }
    }
  }
  if (arr.length) {
    arr.sort((a, b) => b[0] - a[0])
    const re_relay = /中[轉转繼继]/y
    for (const [i, flag] of arr) {
      re_relay.lastIndex = i
      if (!re_relay.test(name)) return `${flag} ${name}`
    }
    return `${arr[0][1]} ${name}`
  }

  for (const [flag, zh] of RE_EMOJI_SINGLE) {
    if (!flags || flag === '🇭🇰' || flag === '🇹🇼' || flag === '🇲🇴') {
      if (zh.test(name)) return `${flag} ${name}`
    }
  }

  for (const [flag, , en] of RE_EMOJI) {
    if (!flags || flag === '🇭🇰' || flag === '🇹🇼' || flag === '🇲🇴') {
      for (const m of name.matchAll(en)) {
        arr.push([m.index + m[0].length, flag])
      }
    }
  }
  if (arr.length) {
    arr.sort((a, b) => b[0] - a[0])
    return `${arr[0][1]} ${name}`
  }

  if (!flags) {
    if (RE_EMOJI_CN.test(name)) return `🇨🇳 ${name}`
    if (!name.includes('ℹ️') && RE_EMOJI_INFO.test(name)) return `ℹ️ ${name}`
  }

  return name
}

function renameDuplicates(proxies: Proxy[]): Proxy[] {
  const counter: Record<string, number> = Object.create(null)
  for (const proxy of proxies) {
    let cnt = counter[proxy.name]
    if (!cnt) {
      counter[proxy.name] = 1
      continue
    }
    let new_name
    do {
      new_name = `${proxy.name} ${++cnt}`
    } while (counter[new_name])
    counter[proxy.name] = cnt
    counter[new_name] = 1
    proxy.name = new_name
  }
  return proxies
}

export async function cvt(
  _from: string,
  _to: string = 'clash',
  ua: string = 'ClashMetaForAndroid/2.11.5.Meta',
  proxy?: string,
): Promise<[string, [number, number, number], Headers | undefined]> {
  // console.time('from')
  const proxy_urls = proxy?.split('|') ?? []
  const promises = _from.split('|').map(async (x, i) => {
    if (/^(?:https?|data):/i.test(x)) {
      try {
        // console.time('fetch')
        const resp = await fetch(x, {
          headers: { 'user-agent': ua },
          ...proxy_urls[i] && {
            client: Deno.createHttpClient({
              proxy: {
                url: proxy_urls[i].replace(
                  /^(https?:|socks5h?:)?\/*/i,
                  (_, $1) => `${$1?.toLowerCase() || 'http:'}//`,
                ),
              },
            }),
          },
        })
        // console.timeEnd('fetch')
        // console.time('text')
        const text = await resp.text()
        // console.timeEnd('text')
        if (resp.ok) return [...from(text), /^data:/i.test(x) ? undefined : resp.headers]
        return [[], 0]
      } catch (e) {
        console.error('Fetch Error:', e)
        return [[], 0]
      }
    }
    return from(x)
  }) as Promise<[Proxy[], number, Headers | undefined]>[]
  let proxies = []
  let total = 0
  const subinfo_headers = []
  const other_headers = []
  for await (const [list, _total, headers] of promises) {
    proxies.push(...list)
    total += _total
    if (headers) {
      if (headers.has('subscription-userinfo')) {
        subinfo_headers.push(headers)
      } else {
        other_headers.push(headers)
      }
    }
  }
  // console.timeEnd('from')
  const count_before_filter = proxies.length
  // console.time('filter')
  proxies = filter(proxies)
  // console.timeEnd('filter')
  // console.time('handleEmoji')
  for (const proxy of proxies) {
    proxy.name = handleEmoji(proxy.name)
  }
  // console.timeEnd('handleEmoji')
  // console.time('renameDuplicates')
  proxies = renameDuplicates(proxies)
  // console.timeEnd('renameDuplicates')
  // console.time('to')
  const result: [string, [number, number, number], Headers | undefined] = [
    proxies.length === 0 && _from !== 'empty'
      ? ''
      : to(proxies, _to === 'auto' ? ua.toLowerCase().includes('clash') ? 'clash' : 'base64' : _to),
    [proxies.length, count_before_filter, total],
    subinfo_headers.length === 1
      ? subinfo_headers[0]
      : subinfo_headers.length === 0 && other_headers.length === 1
      ? other_headers[0]
      : undefined,
  ]
  // console.timeEnd('to')
  return result
}
