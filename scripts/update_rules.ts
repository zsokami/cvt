const rulesets = [
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list', 'DIRECT'],
  ['https://raw.githubusercontent.com/zsokami/ACL4SSR/main/ChinaOnly.list', 'DIRECT'],
  ['https://raw.githubusercontent.com/zsokami/ACL4SSR/main/UnBan1.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/UnBan.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/zsokami/ACL4SSR/main/BanProgramAD1.list', '💩 ‍广告'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list', '💩 ‍广告'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list', '💩 ‍广告'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/BilibiliHMT.list', '📺 ‍B站'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Bilibili.list', '📺 ‍B站'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list', '🤖 ‍AI'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/UnBan.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/ProxyGFWlist.list', '✈️ ‍起飞'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list', '🛩️ ‍墙内'],
]

const supported_types = new Set([
  'DOMAIN',
  'DOMAIN-SUFFIX',
  'DOMAIN-KEYWORD',
  'GEOSITE',
  'IP-CIDR',
  'IP-CIDR6',
  'IP-SUFFIX',
  'IP-ASN',
  'GEOIP',
])

type IPVersion = 4 | 6

class Segment {
  covered = false
  children?: [Segment | null, Segment | null] = [null, null]

  private cover(): void {
    this.covered = true
    delete this.children
  }

  add(prefix: bigint, length: number): boolean {
    if (this.covered) return false

    if (length === 0) {
      this.cover()
      return true
    }

    const nextLength = length - 1
    const bit = Number((prefix >> BigInt(nextLength)) & 1n) as 0 | 1
    const children = this.children!

    let child = children[bit]
    if (child === null) {
      child = new Segment()
      children[bit] = child
    }

    if (!child.add(prefix, nextLength)) return false

    if (child.covered && children[(bit ^ 1) as 0 | 1]?.covered) {
      this.cover()
    }

    return true
  }
}

class IP_CIDR_SegmentTree {
  private root = new Segment()
  private version: IPVersion | null = null

  add(address: string): boolean {
    const slash = address.indexOf('/')
    if (slash !== address.lastIndexOf('/')) throw new TypeError(`Invalid CIDR: ${address}`)

    const ip = slash === -1 ? address : address.slice(0, slash)
    const version: IPVersion = ip.includes(':') ? 6 : 4
    const maxPrefixLen = version === 4 ? 32 : 128
    const prefixLen = slash === -1 ? maxPrefixLen : Number(address.slice(slash + 1))

    if (
      !Number.isInteger(prefixLen) ||
      prefixLen < 0 ||
      prefixLen > maxPrefixLen
    ) {
      throw new TypeError(`Invalid CIDR: ${address}`)
    }

    if (this.version !== null && this.version !== version) {
      throw new TypeError(
        `${address} 的版本 (IPv${version}) 与内部的 (IPv${this.version}) 不一致`,
      )
    }
    this.version = version

    let value: bigint
    if (version === 4) {
      value = IP_CIDR_SegmentTree.parseIPv4(ip)
    } else {
      value = IP_CIDR_SegmentTree.parseIPv6(ip)
    }

    const prefix = value >> BigInt(maxPrefixLen - prefixLen)
    return this.root.add(prefix, prefixLen)
  }

  private static parseIPv4(ip: string): bigint {
    const parts = ip.split('.')
    if (parts.length !== 4) throw new TypeError(`Invalid IP: ${ip}`)

    return parts.reduce((value, part) => {
      if (!/^(0|[1-9]\d{0,2})$/.test(part)) {
        throw new TypeError(`Invalid IP: ${ip}`)
      }
      const octet = Number(part)
      if (octet > 255) throw new TypeError(`Invalid IP: ${ip}`)
      return (value << 8n) | BigInt(octet)
    }, 0n)
  }

  private static parseIPv6(ip: string): bigint {
    if (ip.includes('%')) throw new TypeError(`Invalid IP: ${ip}`)

    if (ip.includes('.')) {
      const colon = ip.lastIndexOf(':')
      if (colon < 0) throw new TypeError(`Invalid IP: ${ip}`)

      const ipv4 = IP_CIDR_SegmentTree.parseIPv4(ip.slice(colon + 1))
      const high = (ipv4 >> 16n).toString(16)
      const low = (ipv4 & 0xffffn).toString(16)
      ip = `${ip.slice(0, colon + 1)}${high}:${low}`
    }

    const compression = ip.indexOf('::')
    let groups: string[]

    if (compression !== -1) {
      if (ip.indexOf('::', compression + 2) !== -1) {
        throw new TypeError(`Invalid IP: ${ip}`)
      }

      const left = ip.slice(0, compression)
      const right = ip.slice(compression + 2)
      const lhs = left ? left.split(':') : []
      const rhs = right ? right.split(':') : []
      const zeros = 8 - lhs.length - rhs.length

      if (zeros < 1) throw new TypeError(`Invalid IP: ${ip}`)
      groups = [...lhs, ...Array(zeros).fill('0'), ...rhs]
    } else {
      groups = ip.split(':')
      if (groups.length !== 8) throw new TypeError(`Invalid IP: ${ip}`)
    }

    if (groups.some((group) => !/^[\da-fA-F]{1,4}$/.test(group))) {
      throw new TypeError(`Invalid IP: ${ip}`)
    }

    return groups.reduce(
      (value, group) => (value << 16n) | BigInt(`0x${group}`),
      0n,
    )
  }
}

class DomainNode {
  flag = 0
  next?: Map<string, DomainNode>
}

class DOMAIN_SUFFIX_Tree {
  private static readonly FLAG_DOMAIN = 1
  private static readonly FLAG_DOMAIN_SUFFIX = 2
  private root = new DomainNode()

  add(domain: string, suffix = true): boolean {
    const flag = suffix ? DOMAIN_SUFFIX_Tree.FLAG_DOMAIN_SUFFIX : DOMAIN_SUFFIX_Tree.FLAG_DOMAIN

    let node = this.root

    for (const part of domain.split('.').reverse()) {
      const next = node.next ?? (node.next = new Map())
      let child = next.get(part)

      if (!child) {
        child = new DomainNode()
        next.set(part, child)
      }

      node = child
      if (node.flag === DOMAIN_SUFFIX_Tree.FLAG_DOMAIN_SUFFIX) {
        return false
      }
    }

    if (flag > node.flag) {
      node.flag = flag
      if (suffix) delete node.next
      return true
    }

    return false
  }
}

function removeRedundantRules(rules: string[]): string[] {
  const keywords: string[] = []
  const domainTree = new DOMAIN_SUFFIX_Tree()
  const ipTrees = new Map<string, IP_CIDR_SegmentTree>()
  const sets = new Map<string, Set<string>>()

  let i = 0

  for (const rule of rules) {
    const parts = rule.split(',')
    const t = parts[0]
    const v = parts[1]

    if (t.startsWith('DOMAIN')) {
      if (keywords.some((w) => v.includes(w))) continue

      if (t === 'DOMAIN-KEYWORD') {
        keywords.push(v)
      } else if (!domainTree.add(v, t === 'DOMAIN-SUFFIX')) {
        continue
      }
    } else if (t.includes('IP-CIDR')) {
      let tree = ipTrees.get(t)
      if (!tree) {
        tree = new IP_CIDR_SegmentTree()
        ipTrees.set(t, tree)
      }
      if (!tree.add(v)) continue
    } else {
      let set = sets.get(t)
      if (!set) {
        set = new Set<string>()
        sets.set(t, set)
      }
      if (set.has(v)) continue
      set.add(v)
    }

    rules[i++] = rule
  }

  rules.length = i
  return rules
}

Deno.writeTextFileSync(
  'netlify/edge-functions/main/rules.ts',
  `export const RULES = \`rules:
${
    removeRedundantRules((await Promise.all(rulesets.map(async ([url, name]) =>
      (await (await fetch(url)).text())
        .match(/^[^#\s].*/mg)
        ?.map((x) => x.split(','))
        .filter((x) => supported_types.has(x[0]))
        .map((x) => {
          x.splice(2, 0, name)
          return '- ' + x.join(',')
        }) ?? []
    ))).flat()).join('\n')
  }
- GEOIP,CN,🛩️ ‍墙内
- MATCH,🌐 ‍未知站点
\``,
)
