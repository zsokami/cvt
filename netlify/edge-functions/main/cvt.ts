import { fromURIs, toURIs } from './uris.ts'
import { fromClash, toClash } from './clash.ts'
import { decodeBase64Url, encodeBase64 } from './utils.ts'
import { geoip } from './geoip.ts'
import { Proxy } from './types.ts'

import { RE_EMOJI, RE_EMOJI_CN, RE_EMOJI_INFO, RE_EMOJI_SINGLE, RE_EXCLUDE } from './consts.ts'

function from(input: string, meta = true): [Proxy[], number, Record<string, number>] {
  // console.time('decodeBase64Url')
  try {
    input = decodeBase64Url(input)
  } catch {
    // pass
  }
  // console.timeEnd('decodeBase64Url')
  // console.time('fromURIs')
  let [proxies, total, count_unsupported] = fromURIs(input, meta)
  // console.timeEnd('fromURIs')
  if (total === 0) {
    // console.time('fromClash')
    ;[proxies, total, count_unsupported] = fromClash(input, meta)
    // console.timeEnd('fromClash')
  }
  return [proxies, total, count_unsupported]
}

function to(
  proxies: Proxy[],
  target = 'clash',
  meta = true,
  ndl = false,
  counts?: [number, number, number],
  count_unsupported?: Record<string, number>,
  errors?: string[],
): string {
  switch (target) {
    case 'clash':
    case 'clash-proxies':
      return toClash(
        proxies,
        target === 'clash-proxies',
        meta,
        ndl,
        counts,
        count_unsupported,
        errors,
      )
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

async function handleEmoji(name: string, server: string): Promise<string> {
  if (name.startsWith('🎏')) return name
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
    if (arr.length > 1) {
      arr.sort((a, b) => b[0] - a[0])
      const re_relay = /中[轉转繼继]/y
      for (const [i, flag] of arr) {
        re_relay.lastIndex = i
        if (!re_relay.test(name)) return `${flag} ${name}`
      }
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
    if (arr.length > 1) {
      arr.sort((a, b) => b[0] - a[0])
      if (/^[\da-z.-]*\.[\da-z.-]*$/i.test(name.slice(arr[arr.length - 1][0], arr[arr.length - 2][0]))) {
        return `${arr[arr.length - 1][1]} ${name}`
      }
      for (let [i, flag] of arr) {
        while ('0' <= name[i] && name[i] <= '9') ++i
        if (name[i] !== '.' && name[i] !== '-') return `${flag} ${name}`
      }
    }
    return `${arr[0][1]} ${name}`
  }

  if (!name.includes('ℹ️')) {
    if (RE_EMOJI_INFO.test(name)) return `ℹ️ ${name}`

    const m = name.match(/(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d)/)
    const flag = (m && await geoip(m[0])) || await geoip(server)
    if (flag) return `${flag} ${name}`

    if (!flags && RE_EMOJI_CN.test(name)) return `🇨🇳 ${name}`
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
  { ua, ndl, proxy }: { ua?: string; ndl?: boolean; proxy?: string } = {},
): Promise<[string, [number, number, number], Headers | undefined]> {
  ua ||= 'ClashMetaForAndroid/2.11.18.Meta'
  const ua_lower = ua.toLowerCase()
  const clash = ua_lower.includes('clash')
  const hiddify = ua_lower.includes('hiddify')
  const meta = !clash || hiddify || /meta|mihomo|verge|nyanpasu/.test(ua_lower)
  if (_to === 'auto') {
    _to = hiddify ? 'clash-proxies' : clash ? 'clash' : 'base64'
  }
  if (hiddify) {
    ua = 'ClashMeta'
  }
  // console.time('from')
  const proxy_urls = proxy?.split('|') ?? []
  const froms = _from.split('|')
  const results = await Promise.allSettled(
    froms.map(async (x, i): Promise<[Proxy[], number, Record<string, number>, Headers?]> => {
      if (/^(?:https?|data):/i.test(x)) {
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
        if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`)
        // console.timeEnd('fetch')
        // console.time('text')
        const text = await resp.text()
        // console.timeEnd('text')
        return [...from(text, meta), /^data:/i.test(x) ? undefined : resp.headers]
      }
      return from(x, meta)
    }),
  )
  let proxies = []
  let total = 0
  const count_unsupported: Record<string, number> = {}
  const subinfo_headers = []
  const other_headers = []
  const errors = []
  for (let i = 0; i < results.length; i++) {
    const result = results[i]
    if (result.status === 'rejected') {
      errors.push(`${froms[i]} ${result.reason}`.replace(/[\r\n]+/g, ''))
      continue
    }
    const [list, _total, _count_unsupported, headers] = result.value
    proxies.push(...list)
    total += _total
    for (const [type, count] of Object.entries(_count_unsupported)) {
      count_unsupported[type] = (count_unsupported[type] || 0) + count
    }
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
    proxy.name = await handleEmoji(proxy.name, proxy.server)
  }
  // console.timeEnd('handleEmoji')
  // console.time('renameDuplicates')
  proxies = renameDuplicates(proxies)
  // console.timeEnd('renameDuplicates')
  // console.time('to')
  const counts = [proxies.length, count_before_filter, total] as [number, number, number]
  const result: [string, [number, number, number], Headers | undefined] = [
    proxies.length === 0 && _from !== 'empty'
      ? errors.length ? `订阅转换失败：\n${errors.join('\n')}` : ''
      : to(proxies, _to, meta, ndl, counts, count_unsupported, errors),
    counts,
    subinfo_headers.length === 1
      ? subinfo_headers[0]
      : subinfo_headers.length === 0 && other_headers.length === 1
      ? other_headers[0]
      : undefined,
  ]
  // console.timeEnd('to')
  return result
}
