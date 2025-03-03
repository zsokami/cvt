import type {
  AnyTLS,
  Empty,
  GRPCNetwork,
  H2Network,
  HTTP,
  HTTPNetwork,
  Hysteria,
  Hysteria2,
  ObfsPlugin,
  PortOrPorts,
  Proxy,
  ProxyBase,
  Reality,
  RestlsPlugin,
  ShadowTlsPlugin,
  Socks5,
  SS,
  SSR,
  Trojan,
  TUIC,
  V2rayPlugin,
  VLESS,
  VMess,
  WireGuard,
  WSNetwork,
} from './types.ts'
import {
  decodeBase64Url,
  encodeBase64,
  encodeBase64Url,
  pickNonEmptyString,
  splitLeft,
  splitRight,
  urlDecode,
  urlDecodePlus,
} from './utils.ts'
import { scv, udp } from './consts.ts'

const FROM_URI = {
  http(uri: string): HTTP {
    const u = new URL(uri)
    let { username, password } = u
    if (!username && !password && !u.port) {
      try {
        const i = uri.indexOf('://') + 3
        const s = splitRight(decodeBase64Url(uri.slice(i, i + u.hostname.length)), '@')
        if (s.length === 2) {
          ;[username, password] = splitLeft(s[0], ':')
        }
        u.host = s[s.length - 1]
      } catch {
        // pass
      }
    } else {
      username = urlDecode(username)
      password = urlDecode(password)
    }
    return {
      ...baseFrom(u),
      ...(username || password) && { username, password },
      ...u.protocol === 'https:' && { tls: true, ...scv },
    }
  },
  socks5(uri: string): Socks5 {
    const u = new URL(uri)
    let { username, password } = u
    if (!username && !password && !u.port) {
      try {
        const s = splitRight(decodeBase64Url(u.hostname), '@')
        if (s.length === 2) {
          ;[username, password] = splitLeft(s[0], ':')
        }
        u.host = s[s.length - 1]
      } catch {
        // pass
      }
    } else {
      username = urlDecode(username)
      password = urlDecode(password)
    }
    return {
      ...baseFrom(u),
      ...(username || password) && { username, password },
      ...udp,
    }
  },
  ss(uri: string): SS {
    const u = new URL(uri)
    let cipher: string, password: string
    if (u.username) {
      ;[cipher, password] = splitLeft(decodeBase64Url(u.username), ':')
    } else {
      const [userinfo, host] = splitRight(decodeBase64Url(u.host), '@')
      u.host = host
      ;[cipher, password] = splitLeft(userinfo, ':')
    }
    return {
      ...baseFrom(u),
      cipher,
      password,
      ...pluginFromSearchParam(u.searchParams.get('plugin')),
      ...udp,
    }
  },
  ssr(uri: string): SSR {
    const [ssr, params = ''] = splitLeft(decodeBase64Url(splitLeft(uri, '://')[1]), '/?')
    const [server, port, protocol, cipher, obfs, password] = splitRight(ssr, ':', 5)
    const { remarks, obfsparam, protoparam } = Object.fromEntries(
      params.split('&').map((s) => splitLeft(s, '=')).map(([k, v]) => [k, decodeBase64Url(v)]),
    )
    return {
      name: remarks || `${server}:${port}`,
      server,
      port: +port,
      type: 'ssr',
      cipher,
      password: decodeBase64Url(password),
      obfs,
      protocol,
      ...obfsparam && { 'obfs-param': obfsparam },
      ...protoparam && { 'protocol-param': protoparam },
      ...udp,
    }
  },
  vmess(uri: string): VMess {
    const j = JSON.parse(decodeBase64Url(splitLeft(uri, '://')[1]))
    const { ps, add, port, id, aid, scy, net, tls, sni, alpn, fp } = j
    const tlsOpts = tls === 'tls' || net === 'grpc' || net === 'h2'
      ? {
        tls: true,
        ...sni && { servername: sni },
        ...alpn && { alpn: alpn.split(',') },
        ...fp && { 'client-fingerprint': fp },
        ...scv,
      }
      : {}
    return {
      name: ps || `${add}:${port}`,
      server: add,
      port: +port,
      type: 'vmess',
      uuid: id,
      alterId: +aid || 0,
      cipher: scy || 'auto',
      ...networkFrom(j),
      ...tlsOpts,
      ...udp,
    }
  },
  vless(uri: string): VLESS {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const { flow, security, sni, alpn, fp, pbk, sid, type } = ps
    const tlsOpts = security === 'tls' || security === 'reality' || type === 'grpc' || type === 'h2'
      ? {
        tls: true,
        ...sni && { servername: sni },
        ...alpn && { alpn: alpn.split(',') },
        ...fp && { 'client-fingerprint': fp },
        ...realityFrom(pbk, sid),
        ...scv,
      }
      : {}
    return {
      ...baseFrom(u),
      uuid: urlDecode(u.username),
      ...networkFrom(ps),
      ...flow && { flow },
      ...tlsOpts,
      ...udp,
    }
  },
  trojan(uri: string): Trojan {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const netOpts = networkFrom(ps.ws === '1' ? { type: 'ws', host: ps.host, path: ps.wspath } : ps)

    if ('network' in netOpts && netOpts.network !== 'ws' && netOpts.network !== 'grpc') {
      throw Error(`Unsupported network: ${netOpts.network}`)
    }

    const { sni, alpn, fp, pbk, sid } = ps
    return {
      ...baseFrom(u),
      password: urlDecode(u.username),
      ...netOpts,
      ...sni && { sni },
      ...alpn && { alpn: alpn.split(',') },
      ...fp && { 'client-fingerprint': fp },
      ...realityFrom(pbk, sid),
      ...scv,
      ...udp,
    }
  },
  hysteria(uri: string): Hysteria {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const { protocol, auth, peer, upmbps, downmbps, alpn, obfsParam, fastopen } = ps
    return {
      ...baseFrom(u),
      ...auth && { 'auth-str': auth },
      up: upmbps,
      down: downmbps,
      ...obfsParam && { obfs: obfsParam },
      ...protocol && protocol !== 'udp' && { protocol },
      ...peer && { sni: peer },
      ...alpn && alpn !== 'hysteria' && { alpn: alpn.split(',') },
      ...scv,
      ...fastopen === '1' && { 'fast-open': true },
    }
  },
  hysteria2(uri: string): Hysteria2 {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const { alpn } = ps
    return {
      ...baseFromForPorts(u),
      password: urlDecode(u.username),
      ...pickNonEmptyString(ps, 'up', 'down', 'obfs', 'obfs-password', 'sni'),
      ...alpn && { alpn: alpn.split(',') },
      ...scv,
    }
  },
  tuic(uri: string): TUIC {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const { alpn, sni, congestion_control } = ps
    return {
      ...baseFrom(u),
      uuid: urlDecode(u.username),
      password: urlDecode(u.password),
      ...alpn && { alpn: alpn.split(',') },
      ...sni && { sni },
      ...congestion_control && { 'congestion-controller': congestion_control },
      ...scv,
    }
  },
  wireguard(uri: string): WireGuard {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const { publickey, reserved, address, mtu } = ps
    const ips = Object.fromEntries(address.split(',').map((x) => [x.includes(':') ? 'ipv6' : 'ip', x]))
    return {
      ...baseFrom(u),
      'private-key': urlDecode(u.username),
      ...publickey && { 'public-key': publickey },
      ...reserved && { reserved: reserved.split(',').map(Number) },
      ...ips,
      ...mtu && { mtu: +mtu },
      ...udp,
    }
  },
  anytls(uri: string): AnyTLS {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const { alpn } = ps
    return {
      ...baseFrom(u),
      password: urlDecode(u.username),
      ...pickNonEmptyString(ps, 'sni'),
      ...alpn && { alpn: alpn.split(',') },
      ...scv,
      ...udp,
    }
  },
}

const TO_URI = {
  http(proxy: Proxy): string {
    checkType(proxy, 'http')
    const { name, server, port, username, password, tls } = proxy
    const auth = (username || password ? `${username}:${password}@` : '') +
      `${server.includes(':') ? `[${server}]` : server}:${port}`
    return `${tls ? 'https' : 'http'}://${encodeBase64Url(auth)}?${new URLSearchParams({ remarks: name })}`
  },
  socks5(proxy: Proxy): string {
    checkType(proxy, 'socks5')
    const { name, server, port, username, password } = proxy
    const auth = (username || password ? `${username}:${password}@` : '') +
      `${server.includes(':') ? `[${server}]` : server}:${port}`
    const u = new URL(`socks://${encodeBase64Url(auth)}`)
    u.hash = name.replaceAll('%', '%25')
    return u.href
  },
  ss(proxy: Proxy): string {
    checkType(proxy, 'ss')
    const { cipher, password } = proxy
    const u = baseTo(proxy)
    u.username = encodeBase64Url(`${cipher}:${password}`)
    const plugin = pluginToSearchParam(proxy)
    if (plugin) {
      u.pathname = '/'
      u.searchParams.set('plugin', plugin)
    }
    return u.href
  },
  ssr(proxy: Proxy): string {
    checkType(proxy, 'ssr')
    const {
      name,
      type,
      server,
      port,
      cipher,
      password,
      obfs,
      protocol,
      'obfs-param': obfsparam,
      'protocol-param': protoparam,
    } = proxy
    const ssr = [server, port, protocol, cipher, obfs, encodeBase64Url(password)].join(':')
    const params = [['remarks', name], ['obfsparam', obfsparam], ['protoparam', protoparam]].filter(([, v]) => v).map((
      [k, v],
    ) => `${k}=${encodeBase64Url(v!)}`).join('&')
    return `${type}://` + encodeBase64Url(`${ssr}/?${params}`)
  },
  vmess(proxy: Proxy): string {
    checkType(proxy, 'vmess')
    const { name, type, server, port, uuid, alterId, cipher, tls, servername, alpn, 'client-fingerprint': fp } = proxy
    return `${type}://` + encodeBase64(JSON.stringify({
      v: '2',
      ps: name,
      add: server,
      port: String(port),
      id: uuid,
      ...alterId && { aid: String(alterId) },
      ...cipher !== 'auto' && { scy: cipher },
      ...networkTo(proxy),
      ...tls && {
        tls: 'tls',
        ...servername && { sni: servername },
        ...alpn?.length && { alpn: alpn.join(',') },
        ...fp && { fp },
      },
    }))
  },
  vless(proxy: Proxy): string {
    checkType(proxy, 'vless')
    const { uuid, flow, tls, servername, alpn, 'client-fingerprint': fp } = proxy
    const u = baseTo(proxy)
    u.username = uuid
    u.search = new URLSearchParams({
      ...networkToStd(proxy),
      ...flow && { flow },
      ...tls && {
        ...realityTo(proxy, { security: 'tls' }),
        ...servername && { sni: servername },
        ...alpn?.length && { alpn: alpn.join(',') },
        ...fp && { fp },
      },
    }).toString()
    return u.href
  },
  trojan(proxy: Proxy): string {
    checkType(proxy, 'trojan')
    const { password, sni, alpn, 'client-fingerprint': fp } = proxy
    const u = baseTo(proxy)
    u.username = password
    u.search = new URLSearchParams({
      ...networkToStd(proxy),
      ...realityTo(proxy),
      ...sni && { sni },
      ...alpn?.length && { alpn: alpn.join(',') },
      ...fp && { fp },
    }).toString()
    return u.href
  },
  hysteria(proxy: Proxy): string {
    checkType(proxy, 'hysteria')
    const { 'auth-str': auth, up, down, obfs, protocol, sni, alpn, 'fast-open': fastopen } = proxy
    const u = baseTo(proxy)
    u.search = new URLSearchParams({
      ...protocol && { protocol },
      ...auth && { auth },
      ...sni && { peer: sni },
      upmbps: toMbps(up),
      downmbps: toMbps(down),
      ...alpn?.length && { alpn: alpn.join(',') },
      ...obfs && { obfs: 'xplus', obfsParam: obfs },
      ...fastopen && { fastopen: '1' },
    }).toString()
    return u.href
  },
  hysteria2(proxy: Proxy): string {
    checkType(proxy, 'hysteria2')
    const { ports, password, up, down, alpn } = proxy
    const u = baseTo(proxy)
    u.username = password
    u.search = new URLSearchParams({
      ...ports && { mport: ports },
      ...up && { up: toMbps(up) },
      ...down && { down: toMbps(down) },
      ...pickNonEmptyString(proxy, 'obfs', 'obfs-password', 'sni'),
      ...alpn?.length && { alpn: alpn.join(',') },
    }).toString()
    return u.href
  },
  tuic(proxy: Proxy): string {
    checkType(proxy, 'tuic')
    const { uuid, password, 'congestion-controller': cc, alpn, sni } = proxy
    const u = baseTo(proxy)
    u.username = uuid || ''
    u.password = password || ''
    u.search = new URLSearchParams({
      ...alpn?.length && { alpn: alpn.join(',') },
      ...sni && { sni },
      ...cc && { congestion_control: cc },
    }).toString()
    return u.href
  },
  wireguard(proxy: Proxy): string {
    checkType(proxy, 'wireguard')
    const { 'private-key': privatekey, 'public-key': publickey, reserved, ip, ipv6, mtu } = proxy
    const u = baseTo(proxy)
    u.username = privatekey
    u.search = new URLSearchParams({
      ...publickey && { publickey },
      ...reserved && { reserved: reserved.join(',') },
      address: [ip, ipv6].filter((x) => x).join(','),
      ...mtu && { mtu: String(mtu) },
    }).toString()
    return u.href
  },
  anytls(proxy: Proxy): string {
    checkType(proxy, 'anytls')
    const { password, alpn } = proxy
    const u = baseTo(proxy)
    u.username = password
    u.search = new URLSearchParams({
      ...pickNonEmptyString(proxy, 'sni'),
      ...alpn?.length && { alpn: alpn.join(',') },
    }).toString()
    return u.href
  },
}

function checkType<T extends Proxy['type']>(proxy: Proxy, type: T): asserts proxy is Proxy & { type: T } {
  if (proxy.type !== type) throw Error(`Proxy type is not ${type}: ${proxy.type}`)
}

function baseFrom<T extends Proxy['type']>(u: URL): ProxyBase & { port: number; type: T } {
  const { protocol, hostname, port, host, hash } = u
  return {
    name: u.searchParams.get('remarks') || hash && urlDecodePlus(hash.substring(1)) || host,
    server: hostname[0] === '[' ? hostname.slice(1, -1) : hostname,
    port: +port || (protocol === 'http:' ? 80 : 443),
    type: TYPE_MAP[protocol.slice(0, -1)] as T,
  }
}

function baseFromForPorts<T extends Proxy['type']>(u: URL): ProxyBase & PortOrPorts & { type: T } {
  const { protocol, hostname, port, host, hash } = u
  const mport = u.searchParams.get('mport')
  const ports = {
    ...port && { port: +port },
    ...mport && { ports: mport },
  }
  if (!('port' in ports || 'ports' in ports)) {
    ports.port = protocol === 'http:' ? 80 : 443
  }
  return {
    name: u.searchParams.get('remarks') || hash && urlDecodePlus(hash.substring(1)) || host,
    server: hostname[0] === '[' ? hostname.slice(1, -1) : hostname,
    ...ports as PortOrPorts,
    type: TYPE_MAP[protocol.slice(0, -1)] as T,
  }
}

function baseTo(p: ProxyBase & Pick<Proxy, 'type'> & { port?: number }): URL {
  const { name, type, server, port } = p
  const u = new URL(`${type}://${server.includes(':') ? `[${server}]` : server}`)
  if (port) u.port = String(port)
  u.hash = name.replaceAll('%', '%25')
  return u
}

function pluginFromSearchParam(p: string | null): Empty | ObfsPlugin | V2rayPlugin | ShadowTlsPlugin {
  if (!p) return {}
  const [plugin, ...strOpts] = p.split(';')
  const opts = Object.fromEntries(strOpts.map((s) => splitLeft(s, '=')))
  switch (plugin) {
    case 'simple-obfs':
    case 'obfs-local': {
      const host = opts['obfs-host']
      return {
        plugin: 'obfs',
        'plugin-opts': {
          mode: opts.obfs,
          ...host && { host },
        },
      } as ObfsPlugin
    }
    case 'v2ray-plugin':
      return {
        plugin,
        'plugin-opts': {
          ...pickNonEmptyString(opts, 'mode', 'host', 'path'),
          ...'tls' in opts && {
            tls: true,
            ...scv,
          },
          ...!('mux' in opts) && { mux: false },
        },
      } as V2rayPlugin
    case 'shadow-tls':
      return {
        plugin,
        'plugin-opts': {
          ...pickNonEmptyString(opts, 'host', 'password'),
          version: +opts.version,
          ...scv,
        },
      } as ShadowTlsPlugin
  }
  throw new Error(`Unsupported plugin: ${plugin}`)
}

function pluginToSearchParam(p: Empty | ObfsPlugin | V2rayPlugin | ShadowTlsPlugin | RestlsPlugin): string {
  if (!('plugin' in p)) return ''
  const { plugin, 'plugin-opts': opts } = p
  switch (plugin) {
    case 'obfs': {
      const { mode, host } = opts
      return `obfs-local;obfs=${mode}${host ? `;obfs-host=${host}` : ''}`
    }
    case 'v2ray-plugin': {
      const { mode, host, path, tls, mux } = opts
      return `${plugin};mode=${mode}${tls ? ';tls' : ''}${mux !== false ? ';mux=4' : ''}${
        host ? `;host=${host}` : ''
      }${path ? `;path=${path}` : ''}`
    }
    case 'shadow-tls': {
      const { host, password, version } = opts
      return `${plugin};host=${host};password=${password}${version ? `;version=${version}` : ''}`
    }
  }
  throw new Error(`Unsupported plugin: ${plugin}`)
}

function networkFrom(
  { net, type, headerType, host, path, serviceName }: Record<string, string | string[]>,
): Empty | WSNetwork | GRPCNetwork | HTTPNetwork | H2Network {
  const network = (headerType || type) === 'http' ? 'http' : (net || type)
  if (!network) return {}
  host = host ? typeof host === 'string' ? host.split(',') : host : []
  path ||= '/'
  switch (network) {
    case 'tcp':
      return {}
    case 'ws':
    case 'httpupgrade':
      return {
        network: 'ws',
        'ws-opts': {
          path,
          ...host.length && { headers: { Host: host[0] } },
          ...network === 'httpupgrade' && { 'v2ray-http-upgrade': true },
        },
      } as WSNetwork
    case 'grpc':
      return {
        network,
        'grpc-opts': {
          'grpc-service-name': serviceName || path,
        },
      } as GRPCNetwork
    case 'http':
      return {
        network,
        'http-opts': {
          path: [path],
          ...host.length && { headers: { Host: host } },
        },
      } as HTTPNetwork
    case 'h2':
      return {
        network,
        'h2-opts': {
          path,
          ...host.length && { host },
        },
      } as H2Network
  }
  throw new Error(`Unsupported network: ${network}`)
}

function networkTo(
  netOpts: Empty | WSNetwork | GRPCNetwork | HTTPNetwork | H2Network,
  kNet = 'net',
  kType = 'type',
  kServiceName = 'path',
) {
  if (!('network' in netOpts)) return {}
  const net = netOpts.network
  switch (net) {
    case 'ws': {
      const { path, headers, 'v2ray-http-upgrade': httpupgrade } = netOpts['ws-opts'] || {}
      return {
        [kNet]: httpupgrade ? 'httpupgrade' : net,
        ...headers?.Host && { host: headers.Host },
        ...path && { path },
      }
    }
    case 'grpc':
      return {
        [kNet]: net,
        ...netOpts['grpc-opts'] && { [kServiceName]: netOpts['grpc-opts']['grpc-service-name'] },
      }
    case 'http': {
      const { path, headers } = netOpts['http-opts'] || {}
      return {
        [kNet]: 'tcp',
        [kType]: 'http',
        ...headers?.Host?.length && { host: headers.Host.join(',') },
        ...path?.length && { path: path[0] },
      }
    }
    case 'h2': {
      const { path, host } = netOpts['h2-opts'] || {}
      return {
        [kNet]: net,
        ...host?.length && { host: host.join(',') },
        ...path && { path },
      }
    }
  }
}

function networkToStd(netOpts: Empty | WSNetwork | GRPCNetwork | HTTPNetwork | H2Network) {
  return networkTo(netOpts, 'type', 'headerType', 'serviceName')
}

function realityFrom(pbk: string, sid?: string): Empty | Reality {
  if (!pbk) return {}
  return {
    'reality-opts': {
      'public-key': pbk,
      'short-id': sid || '',
    },
  } as Reality
}

function realityTo<R extends Record<string, string>>(
  opts: Empty | Reality,
  defaultValue?: R,
): { security?: 'reality'; pbk?: string; sid?: string } | R {
  if (!('reality-opts' in opts)) return defaultValue || {}
  const { 'public-key': pbk, 'short-id': sid } = opts['reality-opts']
  return { security: 'reality', pbk, sid }
}

function toMbps(s: string): string {
  const m = s.match(/^(\d+)\s*([KMGT])?([Bb])ps$/)
  if (!m) return s
  const [, d, u, b] = m
  return (+d * 1e3 ** ('KMGT'.indexOf(u) - 1) * 8 ** +(b === 'B')).toFixed()
}

const TYPE_MAP: Record<
  string,
  | 'http'
  | 'socks5'
  | 'ss'
  | 'ssr'
  | 'vmess'
  | 'vless'
  | 'trojan'
  | 'hysteria'
  | 'hysteria2'
  | 'tuic'
  | 'wireguard'
  | 'anytls'
  | undefined
> = Object.assign(Object.create(null), {
  http: 'http',
  https: 'http',
  socks: 'socks5',
  socks5: 'socks5',
  ss: 'ss',
  ssr: 'ssr',
  vmess: 'vmess',
  vless: 'vless',
  trojan: 'trojan',
  'trojan-go': 'trojan',
  hysteria: 'hysteria',
  hy: 'hysteria',
  hysteria2: 'hysteria2',
  hy2: 'hysteria2',
  tuic: 'tuic',
  wireguard: 'wireguard',
  wg: 'wireguard',
  anytls: 'anytls',
})

export function fromURI(uri: string): Proxy {
  uri = uri.trim()
  const _type = uri.split('://')[0].toLowerCase()
  const type = TYPE_MAP[_type]
  if (!type) throw Error(`Unsupported type: ${_type}`)
  return FROM_URI[type](uri)
}

export function toURI(proxy: Proxy): string {
  const type = TYPE_MAP[proxy.type]
  if (!type) throw Error(`Unsupported type: ${proxy.type}`)
  return TO_URI[type](proxy)
}

export function fromURIs(uris: string): [Proxy[], number] {
  const arr = uris.match(/^[a-z][a-z0-9.+-]*:\/\/.+/gmi) || []
  return [
    arr.flatMap((uri) => {
      try {
        return fromURI(uri)
      } catch {
        return []
      }
    }),
    arr.length,
  ]
}

export function toURIs(proxies: Proxy[]): string {
  return proxies.filter((x) => x.type in TYPE_MAP).map(toURI).join('\n')
}
