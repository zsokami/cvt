import { fromURIs, toURIs } from './uris.ts'
import { fromClash, toClash } from './clash.ts'
import { decodeBase64Url, encodeBase64 } from './utils.ts'
import { geoip } from './geoip.ts'
import { Proxy } from './types.ts'
import { Filter } from './filter.ts'

import { RE_EMOJI, RE_EMOJI_CN, RE_EMOJI_INFO, RE_EMOJI_SINGLE, RE_EXCLUDE } from './consts.ts'

interface Node {
  proxy: Proxy
  flag1?: string
  dialer?: Node
  included?: boolean
}

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
  hide?: string,
  counts?: [number, number, number],
  count_unsupported?: Record<string, number>,
  errors?: string[],
): string {
  try {
    switch (target) {
      case 'clash':
      case 'clash-proxies':
        return toClash(
          proxies,
          target === 'clash-proxies',
          meta,
          ndl,
          hide,
          counts,
          count_unsupported,
          errors,
        )
      case 'uri':
        return toURIs(proxies)
      case 'base64':
        return encodeBase64(toURIs(proxies))
    }
  } catch (e) {
    if (e instanceof SyntaxError) {
      return `订阅转换失败：hide 语法错误：${e.message}`
    }
    throw e
  }
  return `订阅转换失败，不支持的目标格式：${target}`
}

function filter(nodes: Node[], predicate: (proxy: Proxy) => boolean): Node[] {
  const dfs = (node: Node): boolean => {
    if (node.included !== undefined) return node.included
    node.included = false
    const dialerIncluded = node.dialer ? dfs(node.dialer) : true
    return node.included = dialerIncluded && predicate(node.proxy)
  }
  let i = 0
  for (const node of nodes) {
    if (dfs(node)) nodes[i++] = node
  }
  nodes.length = i
  for (const node of nodes) {
    delete node.included
  }
  return nodes
}

function joinEmoji(flag1: string, flag2: string, name: string, joinCN = true): string {
  if (!flag1 || flag1 === flag2) return flag2 && (joinCN || flag2 !== '🇨🇳') ? `${flag2} ${name}` : name
  return `${flag1 === '🇨🇳' ? '' : flag1}->${flag2 || '🎏'} ${name}`
}

async function handleEmoji(name: string, server: string, preFlag1: string): Promise<[string, string]> {
  const flags = name.match(/[🇦-🇿]{2}|🎏/ug)
  const _flag = flags?.find((flag) => flag !== '🇨🇳')
  if (_flag) return [name, _flag]

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
        if (!re_relay.test(name)) return [joinEmoji(preFlag1, flag, name), flag]
      }
    }
    return [joinEmoji(preFlag1, arr[0][1], name), arr[0][1]]
  }

  for (const [flag, zh] of RE_EMOJI_SINGLE) {
    if (!flags || flag === '🇭🇰' || flag === '🇹🇼' || flag === '🇲🇴') {
      if (zh.test(name)) return [joinEmoji(preFlag1, flag, name), flag]
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
        return [joinEmoji(preFlag1, arr[arr.length - 1][1], name), arr[arr.length - 1][1]]
      }
      for (let [i, flag] of arr) {
        while ('0' <= name[i] && name[i] <= '9') ++i
        if (name[i] !== '.' && name[i] !== '-') return [joinEmoji(preFlag1, flag, name), flag]
      }
    }
    return [joinEmoji(preFlag1, arr[0][1], name), arr[0][1]]
  }

  if (!name.includes('ℹ️')) {
    if (RE_EMOJI_INFO.test(name)) return [`ℹ️ ${name}`, '🎏']

    const m = name.match(/(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d)/g)
    let flag1 = m && m.length === 2 ? await geoip(m[0]) : ''
    let flag2 = m ? await geoip(m[m.length - 1]) : ''
    const joinCN = !flags
    if (preFlag1) return [joinEmoji(preFlag1, flag2 || flag1 || await geoip(server), name, joinCN), preFlag1]
    if (flag1 && flag2 && flag1 !== flag2) return [joinEmoji(flag1, flag2, name), flag1]
    flag2 ||= flag1
    flag1 = await geoip(server)
    if (flag1 && flag2 && flag1 !== flag2) return [joinEmoji(flag1, flag2, name), flag1]
    flag2 ||= flag1
    if (flag2 && flag2 !== '🇨🇳') return [`${flag2} ${name}`, flag2]

    if (joinCN && (flag2 || RE_EMOJI_CN.test(name))) return [`🇨🇳 ${name}`, '🇨🇳']
  }

  return [name, '🎏']
}

async function handleAllEmoji(nodes: Node[]): Promise<Node[]> {
  const dfs = async (node: Node): Promise<string> => {
    if (node.flag1) return node.flag1
    const preFlag1 = node.dialer ? await dfs(node.dialer) : ''
    const [name, flag1] = await handleEmoji(node.proxy.name, node.proxy.server, preFlag1)
    node.proxy.name = name
    return node.flag1 = preFlag1 || flag1
  }
  for (const node of nodes) {
    await dfs(node)
  }
  return nodes
}

function renameDuplicates(nodes: Node[]): Node[] {
  const counter: Record<string, number> = Object.create(null)
  for (const node of nodes) {
    let cnt = counter[node.proxy.name]
    if (!cnt) {
      counter[node.proxy.name] = 1
      continue
    }
    let new_name
    do {
      new_name = `${node.proxy.name} ${++cnt}`
    } while (counter[new_name])
    counter[node.proxy.name] = cnt
    counter[new_name] = 1
    node.proxy.name = new_name
  }
  return nodes
}

export async function cvt(
  _from: string,
  _to: string = 'clash',
  { ua, ndl, filter: filterExpr, hide, meta, proxy }: {
    ua?: string
    ndl?: boolean
    filter?: string
    hide?: string
    meta?: boolean
    proxy?: string
  } = {},
): Promise<[string, [number, number, number], Headers | undefined]> {
  ua ||= 'ClashMetaForAndroid/2.11.18.Meta'
  const ua_lower = ua.toLowerCase()
  const clash = ua_lower.includes('clash')
  const hiddify = ua_lower.includes('hiddify')
  meta ??= !clash || hiddify || /meta|mihomo|verge|nyanpasu/.test(ua_lower)
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
  let nodes: Node[] = []
  const name2node: Record<string, Node> = Object.create(null)
  const name2nexts: Record<string, Node[]> = Object.create(null)
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
    for (const proxy of list) {
      const node: Node = { proxy }
      nodes.push(node)
      const nexts = name2nexts[proxy.name]
      if (nexts) {
        for (const next of nexts) {
          next.dialer = node
        }
        delete name2nexts[proxy.name]
      }
      const dialer = proxy['dialer-proxy']
      if (dialer) {
        const dialerNode = name2node[dialer]
        if (dialerNode) {
          node.dialer = dialerNode
        } else {
          ;(name2nexts[dialer] ??= []).push(node)
        }
      }
      name2node[proxy.name] = node
    }
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
  const count_before_filter = nodes.length
  // console.time('filter')
  nodes = filter(nodes, (proxy) => !RE_EXCLUDE.test(proxy.name))
  // console.timeEnd('filter')
  // console.time('handleEmoji')
  nodes = await handleAllEmoji(nodes)
  // console.timeEnd('handleEmoji')
  if (filterExpr) {
    try {
      const f = new Filter(filterExpr)
      nodes = filter(nodes, (proxy) => f.test(proxy))
    } catch (e) {
      if (e instanceof SyntaxError) {
        errors.push(`filter 语法错误：${e.message}`)
        nodes = []
      } else {
        throw e
      }
    }
  }
  // console.time('renameDuplicates')
  nodes = renameDuplicates(nodes)
  // console.timeEnd('renameDuplicates')
  // console.time('to')
  const proxies = nodes.map(({ proxy, dialer }) => {
    if (dialer) proxy['dialer-proxy'] = dialer.proxy.name
    return proxy
  })
  const counts = [proxies.length, count_before_filter, total] as [number, number, number]
  const result: [string, [number, number, number], Headers | undefined] = [
    proxies.length === 0 && _from !== 'empty'
      ? errors.length ? `订阅转换失败：${errors.length === 1 ? errors[0] : '\n' + errors.join('\n')}` : ''
      : to(proxies, _to, meta, ndl, hide, counts, count_unsupported, errors),
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
