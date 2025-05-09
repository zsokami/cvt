import type {
  AnyTLS,
  Empty,
  GostPlugin,
  GRPCNetwork,
  H2Network,
  HTTP,
  HTTPNetwork,
  Hysteria,
  Hysteria2,
  Mieru,
  ObfsPlugin,
  PortOrPortRange,
  PortOrPorts,
  Proxy,
  ProxyBase,
  Reality,
  RestlsPlugin,
  ShadowTlsPlugin,
  Snell,
  Socks5,
  SS,
  SSH,
  SSR,
  Trojan,
  TUIC,
  V2rayPlugin,
  VLESS,
  VMess,
  WireGuard,
  WSNetwork,
} from './types.ts'
import { parseYAML, pickNonEmptyString, pickNumber, pickTrue } from './utils.ts'
import { requireOldClashSupport } from './proxy_utils.ts'
import { RULES, scv, udp } from './consts.ts'

const FROM_CLASH = {
  http(o: unknown): HTTP {
    checkType(o, 'http')
    return {
      ...baseFrom(o),
      ...pickNonEmptyString(o, 'username', 'password'),
      ...!!o.tls && {
        tls: true,
        ...pickNonEmptyString(o, 'sni', 'fingerprint'),
        ...scv,
      },
      ...!!o.headers && typeof o.headers === 'object' && { headers: o.headers as Record<string, string> },
    }
  },
  socks5(o: unknown): Socks5 {
    checkType(o, 'socks5')
    return {
      ...baseFrom(o),
      ...pickNonEmptyString(o, 'username', 'password'),
      ...!!o.tls && {
        tls: true,
        ...pickNonEmptyString(o, 'fingerprint'),
        ...scv,
      },
      ...udp,
    }
  },
  ss(o: unknown): SS {
    checkType(o, 'ss')
    let cipher = String(o.cipher)
    if (cipher.startsWith('AEAD_')) {
      if (cipher === 'AEAD_CHACHA20_POLY1305') {
        cipher = 'chacha20-ietf-poly1305'
      } else {
        cipher = cipher.slice(5).replaceAll('_', '-').toLowerCase()
      }
    }
    return {
      ...baseFrom(o),
      cipher,
      password: String(o.password),
      ...pluginFrom(o),
      ...pickTrue(o, 'udp-over-tcp'),
      ...pickNumber(o, 'udp-over-tcp-version'),
      ...udp,
    }
  },
  ssr(o: unknown): SSR {
    checkType(o, 'ssr')
    return {
      ...baseFrom(o),
      cipher: String(o.cipher),
      password: String(o.password),
      obfs: String(o.obfs),
      protocol: String(o.protocol),
      ...pickNonEmptyString(o, 'obfs-param', 'protocol-param'),
      ...udp,
    }
  },
  mieru(o: unknown): Mieru {
    checkType(o, 'mieru')
    return {
      ...baseFromForPortRange(o),
      username: String(o.username),
      password: String(o.password),
      transport: String(o.transport),
      ...pickNonEmptyString(o, 'multiplexing'),
      ...udp,
    }
  },
  snell(o: unknown): Snell {
    checkType(o, 'snell')
    return {
      ...baseFrom(o),
      psk: String(o.psk),
      ...pickNumber(o, 'version'),
      ...!!o['obfs-opts'] && typeof o['obfs-opts'] === 'object' &&
        { 'obfs-opts': o['obfs-opts'] as Record<string, string> },
      ...udp,
    }
  },
  vmess(o: unknown): VMess {
    checkType(o, 'vmess')
    const networkOpts = networkFrom(o)
    return {
      ...baseFrom(o),
      uuid: String(o.uuid),
      alterId: Number(o.alterId),
      cipher: String(o.cipher),
      ...pickNonEmptyString(o, 'packet-encoding'),
      ...pickTrue(o, 'global-padding', 'authenticated-length'),
      ...networkOpts,
      ...(o.tls || 'network' in networkOpts && (networkOpts.network === 'grpc' || networkOpts.network === 'h2')) && {
        tls: true,
        ...pickNonEmptyString(o, 'servername', 'fingerprint', 'client-fingerprint'),
        ...Array.isArray(o.alpn) && o.alpn.length && { alpn: o.alpn as string[] },
        ...realityFrom(o),
        ...scv,
      },
      ...udp,
    }
  },
  vless(o: unknown): VLESS {
    checkType(o, 'vless')
    const networkOpts = networkFrom(o)
    return {
      ...baseFrom(o),
      uuid: String(o.uuid),
      ...pickNonEmptyString(o, 'flow', 'packet-encoding'),
      ...networkOpts,
      ...(o.tls || 'network' in networkOpts && (networkOpts.network === 'grpc' || networkOpts.network === 'h2')) && {
        tls: true,
        ...pickNonEmptyString(o, 'servername', 'fingerprint', 'client-fingerprint'),
        ...Array.isArray(o.alpn) && o.alpn.length && { alpn: o.alpn as string[] },
        ...realityFrom(o),
        ...scv,
      },
      ...udp,
    }
  },
  trojan(o: unknown): Trojan {
    checkType(o, 'trojan')
    const ssOpts = o['ss-opts'] as Record<string, unknown> | undefined
    return {
      ...baseFrom(o),
      password: String(o.password),
      ...networkFrom(o),
      ...pickNonEmptyString(o, 'sni', 'fingerprint', 'client-fingerprint'),
      ...Array.isArray(o.alpn) && o.alpn.length && { alpn: o.alpn as string[] },
      ...realityFrom(o),
      ...scv,
      ...!!(ssOpts?.enabled && ssOpts.password) && {
        'ss-opts': {
          enabled: true,
          ...pickNonEmptyString(ssOpts, 'method'),
          password: String(ssOpts.password),
        },
      },
      ...udp,
    }
  },
  hysteria(o: unknown): Hysteria {
    checkType(o, 'hysteria')
    return {
      ...baseFromForPorts(o),
      ...!!o['auth_str'] && { 'auth-str': String(o['auth_str']) },
      ...pickNonEmptyString(o, 'auth-str'),
      ...pickNumber(o, 'hop-interval'),
      up: String(o.up),
      down: String(o.down),
      ...pickNonEmptyString(o, 'obfs', 'protocol', 'sni', 'fingerprint', 'ca-str'),
      ...Array.isArray(o.alpn) && o.alpn.length && { alpn: o.alpn as string[] },
      ...scv,
      ...pickNumber(o, 'recv-window-conn', 'recv-window'),
      ...pickTrue(o, 'disable-mtu-discovery', 'fast-open'),
    }
  },
  hysteria2(o: unknown): Hysteria2 {
    checkType(o, 'hysteria2')
    return {
      ...baseFromForPorts(o),
      password: String(o.password || o.auth),
      ...pickNumber(o, 'hop-interval'),
      ...pickNonEmptyString(o, 'up', 'down', 'obfs', 'obfs-password', 'sni', 'fingerprint', 'ca-str'),
      ...Array.isArray(o.alpn) && o.alpn.length && { alpn: o.alpn as string[] },
      ...scv,
      ...pickNumber(o, 'cwnd', 'udp-mtu'),
    }
  },
  tuic(o: unknown): TUIC {
    checkType(o, 'tuic')
    return {
      ...baseFrom(o),
      ...pickNonEmptyString(
        o,
        'token',
        'uuid',
        'password',
        'ip',
        'congestion-controller',
        'udp-relay-mode',
        'sni',
        'fingerprint',
        'ca-str',
      ),
      ...Array.isArray(o.alpn) && o.alpn.length && { alpn: o.alpn as string[] },
      ...scv,
      ...pickNumber(
        o,
        'max-udp-relay-packet-size',
        'heartbeat-interval',
        'request-timeout',
        'max-open-streams',
        'cwnd',
        'recv-window-conn',
        'recv-window',
        'max-datagram-frame-size',
        'udp-over-stream-version',
      ),
      ...pickTrue(o, 'reduce-rtt', 'fast-open', 'disable-mtu-discovery', 'udp-over-stream', 'disable-sni'),
    }
  },
  wireguard(o: unknown): WireGuard {
    checkType(o, 'wireguard')
    return {
      ...baseFrom(o),
      'private-key': String(o['private-key']),
      ...pickNonEmptyString(o, 'public-key', 'pre-shared-key', 'ip', 'ipv6'),
      ...Array.isArray(o.reserved) && o.reserved.length && { reserved: o.reserved as number[] },
      ...Array.isArray(o['allowed-ips']) && o['allowed-ips'].length && { 'allowed-ips': o['allowed-ips'] as string[] },
      ...pickNumber(o, 'workers', 'mtu', 'persistent-keepalive', 'refresh-server-ip-interval'),
      ...!!o['amnezia-wg-option'] && typeof o['amnezia-wg-option'] === 'object' &&
        {
          'amnezia-wg-option': o['amnezia-wg-option'] as {
            jc: number
            jmin: number
            jmax: number
            s1: number
            s2: number
            h1: number
            h2: number
            h4: number
            h3: number
          },
        },
      ...pickTrue(o, 'remote-dns-resolve'),
      ...Array.isArray(o.dns) && o.dns.length && { dns: o.dns as string[] },
      ...udp,
    }
  },
  ssh(o: unknown): SSH {
    checkType(o, 'ssh')
    return {
      ...baseFrom(o),
      username: String(o.username),
      ...pickNonEmptyString(o, 'password', 'private-key', 'private-key-passphrase'),
      ...Array.isArray(o['host-key']) && o['host-key'].length && { 'host-key': o['host-key'] as string[] },
      ...Array.isArray(o['host-key-algorithms']) && o['host-key-algorithms'].length &&
        { 'host-key-algorithms': o['host-key-algorithms'] as string[] },
    }
  },
  anytls(o: unknown): AnyTLS {
    checkType(o, 'anytls')
    return {
      ...baseFrom(o),
      password: String(o.password),
      ...pickNonEmptyString(o, 'sni', 'fingerprint', 'client-fingerprint'),
      ...Array.isArray(o.alpn) && o.alpn.length && { alpn: o.alpn as string[] },
      ...scv,
      ...udp,
      ...pickNumber(o, 'idle-session-check-interval', 'idle-session-timeout', 'min-idle-session'),
    }
  },
}

function checkType<T extends Proxy['type']>(o: unknown, type: T): asserts o is { type: T; [key: string]: unknown } {
  if (!(o && typeof o === 'object' && 'type' in o)) throw new Error('Invalid proxy')
  if (o.type !== type) throw new Error(`Proxy type is not ${type}: ${o.type}`)
}

function baseFrom<T extends Proxy['type']>(
  o: { type: T; [key: string]: unknown },
): ProxyBase & { port: number; type: T } {
  if (!('name' in o && 'server' in o && 'port' in o)) throw new Error('Invalid proxy')
  return {
    name: String(o.name),
    server: String(o.server),
    port: Number(o.port),
    type: o.type,
    ...pickTrue(o, 'tfo', 'mptcp'),
    ...pickNonEmptyString(o, 'ip-version', 'interface-name'),
    ...pickNumber(o, 'routing-mark'),
  }
}

function baseFromForPorts<T extends Proxy['type']>(
  o: { type: T; [key: string]: unknown },
): ProxyBase & PortOrPorts & { type: T } {
  if (!('name' in o && 'server' in o)) throw new Error('Invalid proxy')
  const ports = {
    ...pickNumber(o, 'port'),
    ...pickNonEmptyString(o, 'ports'),
  }
  if (!('port' in ports || 'ports' in ports)) throw new Error('Invalid proxy')
  return {
    name: String(o.name),
    server: String(o.server),
    ...ports as PortOrPorts,
    type: o.type,
    ...pickTrue(o, 'tfo', 'mptcp'),
    ...pickNonEmptyString(o, 'ip-version', 'interface-name'),
    ...pickNumber(o, 'routing-mark'),
  }
}

function baseFromForPortRange<T extends Proxy['type']>(
  o: { type: T; [key: string]: unknown },
): ProxyBase & PortOrPortRange & { type: T } {
  if (!('name' in o && 'server' in o)) throw new Error('Invalid proxy')
  const ports = {
    ...pickNumber(o, 'port'),
    ...pickNonEmptyString(o, 'port-range'),
  }
  if (!('port' in ports || 'port-range' in ports)) throw new Error('Invalid proxy')
  return {
    name: String(o.name),
    server: String(o.server),
    ...ports as PortOrPortRange,
    type: o.type,
    ...pickTrue(o, 'tfo', 'mptcp'),
    ...pickNonEmptyString(o, 'ip-version', 'interface-name'),
    ...pickNumber(o, 'routing-mark'),
  }
}

function pluginFrom(
  o: { type: 'ss'; [key: string]: unknown },
): Empty | ObfsPlugin | V2rayPlugin | GostPlugin | ShadowTlsPlugin | RestlsPlugin {
  const { plugin } = o
  const opts = o['plugin-opts'] as Record<string, unknown> | undefined
  if (opts && typeof opts === 'object') {
    switch (plugin) {
      case 'obfs':
        return {
          plugin,
          'plugin-opts': {
            mode: String(opts.mode),
            ...pickNonEmptyString(opts, 'host'),
          },
        }
      case 'v2ray-plugin':
        return {
          plugin,
          'plugin-opts': {
            mode: String(opts.mode),
            ...pickNonEmptyString(opts, 'host', 'path'),
            ...!!opts.tls && {
              tls: true,
              ...pickNonEmptyString(opts, 'fingerprint'),
              ...scv,
            },
            ...!!opts.headers && typeof opts.headers === 'object' &&
              { headers: opts.headers as Record<string, string> },
            ...opts.mux === false && { mux: false },
            ...pickTrue(opts, 'v2ray-http-upgrade', 'v2ray-http-upgrade-fast-open'),
          },
        }
      case 'gost-plugin':
        return {
          plugin,
          'plugin-opts': {
            mode: String(opts.mode),
            ...pickNonEmptyString(opts, 'host', 'path'),
            ...!!opts.tls && {
              tls: true,
              ...pickNonEmptyString(opts, 'fingerprint'),
              ...scv,
            },
            ...!!opts.headers && typeof opts.headers === 'object' &&
              { headers: opts.headers as Record<string, string> },
            ...opts.mux === false && { mux: false },
          },
        }
      case 'shadow-tls':
        return {
          plugin,
          ...pickNonEmptyString(o, 'client-fingerprint'),
          'plugin-opts': {
            host: String(opts.host),
            password: String(opts.password),
            ...pickNumber(opts, 'version'),
            ...pickNonEmptyString(opts, 'fingerprint'),
            ...scv,
          },
        }
      case 'restls':
        return {
          plugin,
          ...pickNonEmptyString(o, 'client-fingerprint'),
          'plugin-opts': {
            host: String(opts.host),
            password: String(opts.password),
            'version-hint': String(opts['version-hint']),
            ...pickNonEmptyString(opts, 'restls-script'),
          },
        }
    }
  }
  if (o.obfs) {
    return {
      plugin: 'obfs',
      'plugin-opts': {
        mode: String(o.obfs),
        ...!!o['obfs-host'] && { host: String(o['obfs-host']) },
      },
    }
  }
  return {}
}

function networkFrom(o: Record<string, unknown>): Empty | WSNetwork | GRPCNetwork | HTTPNetwork | H2Network {
  const { network } = o
  switch (network) {
    case 'ws': {
      const opts1 = o['ws-opts'] as Record<string, unknown>
      const opts2 = !!opts1 && typeof opts1 === 'object'
        ? {
          ...pickNonEmptyString(opts1, 'path'),
          ...!!opts1.headers && typeof opts1.headers === 'object' &&
            { headers: opts1.headers as Record<string, string> },
          ...pickNumber(opts1, 'max-early-data'),
          ...pickNonEmptyString(opts1, 'early-data-header-name'),
          ...pickTrue(opts1, 'v2ray-http-upgrade', 'v2ray-http-upgrade-fast-open'),
        }
        : {
          ...!!o['ws-path'] && { path: String(o['ws-path']) },
          ...!!o['ws-headers'] && typeof o['ws-headers'] === 'object' &&
            { headers: o['ws-headers'] as Record<string, string> },
        }
      return {
        network,
        ...Object.keys(opts2).length && { 'ws-opts': opts2 },
      }
    }
    case 'grpc': {
      const opts1 = o['grpc-opts'] as Record<string, unknown>
      const opts2 = !!opts1 && typeof opts1 === 'object'
        ? {
          ...pickNonEmptyString(opts1, 'grpc-service-name'),
        }
        : {}
      return {
        network,
        ...Object.keys(opts2).length && { 'grpc-opts': opts2 },
      }
    }
    case 'http': {
      const opts1 = o['http-opts'] as Record<string, unknown>
      const opts2 = !!opts1 && typeof opts1 === 'object'
        ? {
          ...pickNonEmptyString(opts1, 'method'),
          ...Array.isArray(opts1.path) && opts1.path.length && { path: opts1.path },
          ...!!opts1.headers && typeof opts1.headers === 'object' &&
            { headers: opts1.headers as Record<string, string[]> },
        }
        : {}
      return {
        network,
        ...Object.keys(opts2).length && { 'http-opts': opts2 },
      }
    }
    case 'h2': {
      const opts1 = o['h2-opts'] as Record<string, unknown>
      const opts2 = !!opts1 && typeof opts1 === 'object'
        ? {
          ...pickNonEmptyString(opts1, 'path'),
          ...Array.isArray(opts1.host) && opts1.host.length && { host: opts1.host },
        }
        : {}
      return {
        network,
        ...Object.keys(opts2).length && { 'h2-opts': opts2 },
      }
    }
  }
  return {}
}

function realityFrom(o: Record<string, unknown>): Empty | Reality {
  const opts1 = o['reality-opts'] as Record<string, unknown>
  return !!opts1 && typeof opts1 === 'object'
    ? {
      'reality-opts': {
        'public-key': String(opts1['public-key']),
        'short-id': String(opts1['short-id'] || ''),
      },
    }
    : {}
}

export function fromClash(clash: string, meta = true): [Proxy[], number] {
  try {
    const doc = parseYAML(clash) as { proxies?: unknown; Proxy?: unknown }
    if (!doc) return [[], 0]
    const proxies = doc.proxies || doc.Proxy
    if (!Array.isArray(proxies)) return [[], 0]
    return [
      proxies.flatMap((x) => {
        if (!x || !(x.type in FROM_CLASH)) return []
        try {
          const proxy = FROM_CLASH[x.type as keyof typeof FROM_CLASH](x)
          if (!meta) requireOldClashSupport(proxy)
          return proxy
        } catch {
          return []
        }
      }),
      proxies.length,
    ]
  } catch {
    return [[], 0]
  }
}

function genProxyGroups(proxies: Proxy[], meta = true) {
  const reject = ['REJECT', ...meta ? ['REJECT-DROP'] : []]
  const all = proxies.map((x) => x.name)
  const map: Record<string, string[]> = {
    '🇭🇰 ‍香港': [],
    '🇹🇼 ‍台湾': [],
    '🇨🇳 ‍中国': [],
    '🇸🇬 ‍新加坡': [],
    '🇯🇵 ‍日本': [],
    '🇺🇸 ‍美国': [],
    '🎏 ‍其他': [],
  }
  for (const name of all) {
    const flags = name.match(/[🇦-🇿]{2}/ug)
    if (!flags) {
      map['🎏 ‍其他'].push(name)
      continue
    }
    switch (flags[flags.length - 1]) {
      case '🇨🇳': {
        let i = flags.length
        while (--i > 0 && flags[i] === '🇨🇳');
        if (flags[i] === '🇭🇰') {
          map['🇭🇰 ‍香港'].push(name)
        } else if (flags[i] === '🇹🇼') {
          map['🇹🇼 ‍台湾'].push(name)
        }
        map['🇨🇳 ‍中国'].push(name)
        break
      }
      case '🇭🇰':
        map['🇭🇰 ‍香港'].push(name)
        map['🇨🇳 ‍中国'].push(name)
        break
      case '🇹🇼':
        map['🇹🇼 ‍台湾'].push(name)
        map['🇨🇳 ‍中国'].push(name)
        break
      case '🇲🇴':
        map['🇨🇳 ‍中国'].push(name)
        break
      case '🇸🇬':
        map['🇸🇬 ‍新加坡'].push(name)
        break
      case '🇯🇵':
        map['🇯🇵 ‍日本'].push(name)
        break
      case '🇺🇸':
      case '🇺🇲':
        map['🇺🇸 ‍美国'].push(name)
        break
      default:
        map['🎏 ‍其他'].push(name)
        break
    }
  }
  if (map['🇭🇰 ‍香港'].length === map['🇨🇳 ‍中国'].length || map['🇹🇼 ‍台湾'].length === map['🇨🇳 ‍中国'].length) {
    delete map['🇨🇳 ‍中国']
  }
  for (const [k, v] of Object.entries(map)) {
    if (v.length === 0) {
      delete map[k]
    }
  }
  const entries = Object.entries(map)
  let us_only = false
  if (entries.length === 1) {
    us_only = entries[0][0] === '🇺🇸 ‍美国'
    delete map[entries[0][0]]
    entries.pop()
  }
  const groups: {
    name: string
    proxies: string[]
    type: string
    url?: string
    interval?: number
    tolerance?: number
  }[] = [{ name: '✈️ ‍起飞', proxies: [], type: 'select' }]
  const url = 'https://i.ytimg.com/generate_204'
  const min_interval = 15
  const small_tolerance = 100
  const large_tolerance = 300
  if (all.length) {
    groups.push({
      name: '⚡ ‍低延迟',
      proxies: all,
      type: 'url-test',
      url,
      interval: Math.max(min_interval, all.length),
      tolerance: us_only ? large_tolerance : small_tolerance,
    })
    groups[0].proxies.push('⚡ ‍低延迟')
    groups.push({ name: '👆🏻 ‍指定', proxies: all, type: 'select' })
    groups[0].proxies.push('👆🏻 ‍指定')
  }
  groups.push({ name: '🛩️ ‍墙内', proxies: ['DIRECT', ...reject, '✈️ ‍起飞'], type: 'select' })
  groups.push({ name: '💩 ‍广告', proxies: [...reject, ...meta ? ['PASS'] : [], '🛩️ ‍墙内', '✈️ ‍起飞'], type: 'select' })
  groups.push({
    name: '📺 ‍B站',
    proxies: [
      '🛩️ ‍墙内',
      ...['🇭🇰 ‍香港', '🇹🇼 ‍台湾', '🇨🇳 ‍中国'].filter((x) => x in map),
      '✈️ ‍起飞',
      ...['🇭🇰 ‍香港', '🇹🇼 ‍台湾', '🇨🇳 ‍中国'].filter((x) => x in map).map((x) => '👆🏻' + x),
      ...all.length ? ['👆🏻 ‍指定'] : [],
    ],
    type: 'select',
  })
  groups.push({
    name: '🤖 ‍AI',
    proxies: [
      ...['🇺🇸 ‍美国', '🇹🇼 ‍台湾', '🇸🇬 ‍新加坡', '🇯🇵 ‍日本', '🎏 ‍其他'].filter((x) => x in map),
      '✈️ ‍起飞',
      ...['🇺🇸 ‍美国', '🇹🇼 ‍台湾', '🇸🇬 ‍新加坡', '🇯🇵 ‍日本', '🎏 ‍其他'].filter((x) => x in map).map((x) => '👆🏻' + x),
      ...all.length ? ['👆🏻 ‍指定'] : [],
      '🛩️ ‍墙内',
    ],
    type: 'select',
  })
  groups.push({ name: '🌐 ‍未知站点', proxies: ['✈️ ‍起飞', '🛩️ ‍墙内', '💩 ‍广告'], type: 'select' })
  for (const [k, v] of entries) {
    groups.push({
      name: k,
      proxies: v,
      type: 'url-test',
      url,
      interval: Math.max(min_interval, v.length),
      tolerance: k === '🇺🇸 ‍美国' ? large_tolerance : small_tolerance,
    })
    groups[0].proxies.push(k)
  }
  for (const [k, v] of entries) {
    const name = '👆🏻' + k
    groups.push({ name, proxies: v, type: 'select' })
    groups[0].proxies.push(name)
  }
  groups[0].proxies.push('DIRECT', ...reject)
  return groups
}

export function toClash(proxies: Proxy[], proxiesOnly = false, meta = true): string {
  if (proxiesOnly) {
    return ['proxies:\n', ...proxies.map((x) => `- ${JSON.stringify(x)}\n`)].join('')
  }
  return [
    'mixed-port: 7890\n',
    'allow-lan: true\n',
    'external-controller: :9090\n',
    'unified-delay: true\n',
    'tcp-concurrent: true\n',
    'global-client-fingerprint: chrome\n',
    'proxies:\n',
    ...proxies.map((x) => `- ${JSON.stringify(x)}\n`),
    'proxy-groups:\n',
    ...genProxyGroups(proxies, meta).map((x) => `- ${JSON.stringify(x)}\n`),
    RULES,
  ].join('')
}
