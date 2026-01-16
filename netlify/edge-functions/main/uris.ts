import type {
  AnyTLS,
  GostPlugin,
  GRPCNetwork,
  H2Network,
  HTTP,
  HTTPNetwork,
  Hysteria,
  Hysteria2,
  KcpTunPlugin,
  ObfsPlugin,
  Option,
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
  createPure,
  decodeBase64Url,
  encodeBase64,
  encodeBase64Url,
  pickNonEmptyString,
  pickNumber,
  splitLeft,
  splitRight,
  urlDecode,
  urlDecodePlus,
} from './utils.ts'
import { requireOldClashSupport } from './proxy_utils.ts'
import {
  DEFAULT_CLIENT_FINGERPRINT,
  DEFAULT_GRPC_USER_AGENT,
  DEFAULT_SCV,
  DEFAULT_UDP,
  TYPES_OLD_CLASH_SUPPORTED,
} from './consts.ts'

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
      ...u.protocol === 'https:' && { tls: true, 'skip-cert-verify': DEFAULT_SCV },
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
      ...u.protocol === 'socks5+tls:' && { tls: true, 'skip-cert-verify': DEFAULT_SCV },
      udp: DEFAULT_UDP,
    }
  },
  ss(uri: string): SS {
    const u = new URL(uri)
    let cipher: string, password: string
    if (u.username) {
      ;[cipher, password] = u.password ? [u.username, u.password] : splitLeft(decodeBase64Url(u.username), ':')
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
      udp: DEFAULT_UDP,
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
      cipher: cipher === 'none' ? 'dummy' : cipher,
      password: decodeBase64Url(password),
      obfs,
      protocol,
      ...obfsparam && { 'obfs-param': obfsparam },
      ...protoparam && { 'protocol-param': protoparam },
      udp: DEFAULT_UDP,
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
        'client-fingerprint': fp || DEFAULT_CLIENT_FINGERPRINT,
        'skip-cert-verify': DEFAULT_SCV,
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
      udp: DEFAULT_UDP,
      ...DEFAULT_UDP && { 'packet-encoding': 'xudp' },
    }
  },
  vless(uri: string): VLESS {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const { flow, security, sni, alpn, fp, pbk, sid, type, encryption } = ps
    const tlsOpts = security === 'tls' || security === 'reality' || type === 'grpc' || type === 'h2'
      ? {
        tls: true,
        ...sni && { servername: sni },
        ...alpn && { alpn: alpn.split(',') },
        'client-fingerprint': fp || DEFAULT_CLIENT_FINGERPRINT,
        ...realityFrom(pbk, sid),
        'skip-cert-verify': DEFAULT_SCV,
      }
      : {}
    return {
      ...baseFrom(u),
      uuid: urlDecode(u.username),
      ...networkFrom(ps),
      ...flow && { flow },
      ...encryption && encryption !== 'none' && { encryption },
      ...tlsOpts,
      udp: DEFAULT_UDP,
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
      'client-fingerprint': fp || DEFAULT_CLIENT_FINGERPRINT,
      ...realityFrom(pbk, sid),
      'skip-cert-verify': DEFAULT_SCV,
      udp: DEFAULT_UDP,
    }
  },
  hysteria(uri: string): Hysteria {
    const u = new URL(uri)
    const ps = Object.fromEntries(u.searchParams)
    const { protocol, auth, auth_str, peer, upmbps, downmbps, alpn, obfsParam, fastopen } = ps
    return {
      ...baseFrom(u),
      ...(auth || auth_str) && { 'auth-str': auth || auth_str },
      up: upmbps,
      down: downmbps,
      ...obfsParam && { obfs: obfsParam },
      ...protocol && protocol !== 'udp' && { protocol },
      ...peer && { sni: peer },
      ...alpn && alpn !== 'hysteria' && { alpn: alpn.split(',') },
      'skip-cert-verify': DEFAULT_SCV,
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
      'skip-cert-verify': DEFAULT_SCV,
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
      'skip-cert-verify': DEFAULT_SCV,
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
      udp: DEFAULT_UDP,
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
      'skip-cert-verify': DEFAULT_SCV,
      udp: DEFAULT_UDP,
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
    const ssr = [
      server,
      port,
      protocol,
      cipher === 'dummy' ? 'none' : cipher,
      obfs,
      encodeBase64Url(password),
    ].join(':')
    const params = [['remarks', name], ['obfsparam', obfsparam], ['protoparam', protoparam]]
      .filter(([, v]) => v)
      .map(([k, v]) => `${k}=${encodeBase64Url(v!)}`)
      .join('&')
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
    const { uuid, flow, encryption, tls, servername, alpn, 'client-fingerprint': fp } = proxy
    const u = baseTo(proxy)
    u.username = uuid
    u.search = new URLSearchParams({
      ...networkToStd(proxy),
      ...flow && { flow },
      ...encryption && { encryption },
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

function pluginFromSearchParam(p: string | null): Option<ObfsPlugin | V2rayPlugin | GostPlugin | ShadowTlsPlugin> {
  if (!p) return {}
  const [plugin, ...strOpts] = p.split(';')
  const opts: Record<string, string | undefined> = Object.fromEntries(strOpts.map((s) => splitLeft(s, '=')))
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
            'skip-cert-verify': DEFAULT_SCV,
          },
          ...!('mux' in opts) && { mux: false },
        },
      } as V2rayPlugin
    case 'gost-plugin':
      return {
        plugin,
        'plugin-opts': {
          ...pickNonEmptyString(opts, 'mode', 'host', 'path'),
          ...'tls' in opts && {
            tls: true,
            'skip-cert-verify': DEFAULT_SCV,
          },
          ...!('mux' in opts) && { mux: false },
        },
      } as GostPlugin
    case 'shadow-tls':
      return {
        plugin,
        'plugin-opts': {
          host: opts.host || '',
          ...pickNonEmptyString(opts, 'password'),
          ...pickNumber(opts, 'version'),
          ...opts.alpn && { alpn: opts.alpn.split(',') },
          'skip-cert-verify': DEFAULT_SCV,
        },
      }
  }
  throw new Error(`Unsupported plugin: ${plugin}`)
}

function pluginToSearchParam(
  p: Option<ObfsPlugin | V2rayPlugin | GostPlugin | ShadowTlsPlugin | RestlsPlugin | KcpTunPlugin>,
): string {
  const { plugin, 'plugin-opts': opts } = p
  if (!plugin) return ''
  switch (plugin) {
    case 'obfs': {
      const { mode, host } = opts
      return `obfs-local;obfs=${mode}${host ? `;obfs-host=${host}` : ''}`
    }
    case 'v2ray-plugin':
    case 'gost-plugin': {
      const { mode, host, path, tls, mux } = opts
      return `${plugin};mode=${mode}${tls ? ';tls' : ''}${mux !== false ? ';mux=4' : ''}${
        host ? `;host=${host}` : ''
      }${path ? `;path=${path}` : ''}`
    }
    case 'shadow-tls': {
      const { host, password, version, alpn } = opts
      return `${plugin};host=${host}${password ? `;password=${password}` : ''}${version ? `;version=${version}` : ''}${
        alpn?.length ? `;alpn=${alpn}` : ''
      }`
    }
  }
  throw new Error(`Unsupported plugin: ${plugin}`)
}

function networkFrom(
  { net, type, headerType, host, path, serviceName }: Record<string, string>,
): Option<WSNetwork | GRPCNetwork | HTTPNetwork | H2Network> {
  const network = (headerType || type) === 'http' ? 'http' : (net || type)
  if (!network) return {}
  const hosts = host ? host.split(',') : []
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
          ...hosts.length && { headers: { Host: hosts[0] } },
          ...network === 'httpupgrade' && { 'v2ray-http-upgrade': true },
        },
      }
    case 'grpc':
      return {
        network,
        'grpc-opts': {
          'grpc-service-name': serviceName || path,
          'grpc-user-agent': DEFAULT_GRPC_USER_AGENT,
        },
      }
    case 'http':
      return {
        network,
        'http-opts': {
          path: [path],
          ...hosts.length && { headers: { Host: hosts } },
        },
      }
    case 'h2':
      return {
        network,
        'h2-opts': {
          path,
          ...hosts.length && { host: hosts },
        },
      }
  }
  throw new Error(`Unsupported network: ${network}`)
}

function networkTo(
  netOpts: Option<WSNetwork | GRPCNetwork | HTTPNetwork | H2Network>,
  kNet = 'net',
  kType = 'type',
  kServiceName = 'path',
) {
  const net = netOpts.network
  if (!net) return {}
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

function networkToStd(netOpts: Option<WSNetwork | GRPCNetwork | HTTPNetwork | H2Network>) {
  return networkTo(netOpts, 'type', 'headerType', 'serviceName')
}

function realityFrom(pbk: string, sid?: string): Option<Reality> {
  if (!pbk) return {}
  return {
    'reality-opts': {
      'public-key': pbk,
      'short-id': sid || '',
    },
  }
}

function realityTo<R extends Record<string, string>>(
  opts: Option<Reality>,
  defaultValue?: R,
): { security?: 'reality'; pbk?: string; sid?: string } | R {
  const realityOpts = opts['reality-opts']
  if (!realityOpts) return defaultValue || {}
  const { 'public-key': pbk, 'short-id': sid } = realityOpts
  return { security: 'reality', pbk, sid }
}

function toMbps(s: string): string {
  const m = s.match(/^(\d+)\s*([KMGT])?([Bb])ps$/)
  if (!m) return s
  const [, d, u, b] = m
  return (+d * 1e3 ** ('KMGT'.indexOf(u) - 1) * 8 ** +(b === 'B')).toFixed()
}

const TYPE_MAP: Record<string, keyof typeof FROM_URI | undefined> = createPure({
  http: 'http',
  https: 'http',
  socks: 'socks5',
  socks5: 'socks5',
  socks5h: 'socks5',
  'socks5+tls': 'socks5',
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

export function fromURI(uri: string, meta = true): Proxy {
  uri = uri.trim()
  const _type = uri.split('://')[0].toLowerCase()
  const type = TYPE_MAP[_type]
  if (!type || (!meta && !TYPES_OLD_CLASH_SUPPORTED.has(type))) throw Error(`Unsupported type: ${_type}`)
  const proxy = FROM_URI[type](uri)
  if (!meta) requireOldClashSupport(proxy)
  return proxy
}

export function toURI(proxy: Proxy): string {
  const type = TYPE_MAP[proxy.type]
  if (!type) throw Error(`Unsupported type: ${proxy.type}`)
  return TO_URI[type](proxy)
}

export function fromURIs(uris: string, meta = true): [Proxy[], number, Record<string, number>] {
  let total = 0
  const count_unsupported: Record<string, number> = {}
  const arr = [
    ...uris.matchAll(/^([a-z][a-z0-9.+-]*):\/\/.+/gmi).flatMap(([uri, type]) => {
      total++
      try {
        return [fromURI(uri, meta)]
      } catch {
        type = type.toLowerCase()
        type = TYPE_MAP[type] || type
        count_unsupported[type] = (count_unsupported[type] || 0) + 1
        return []
      }
    }),
  ]
  return [
    arr,
    total,
    count_unsupported,
  ]
}

export function toURIs(proxies: Proxy[]): string {
  return proxies.filter((x) => x.type in TYPE_MAP).map(toURI).join('\n')
}
