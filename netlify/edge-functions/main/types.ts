// deno-lint-ignore ban-types
export type Empty = {}

export interface ProxyBase {
  name: string
  server: string
  tfo?: boolean
  mptcp?: boolean
  'ip-version'?: string
  'interface-name'?: string
  'routing-mark'?: number
}

export interface HTTP extends ProxyBase {
  type: 'http'
  port: number
  username?: string
  password?: string
  tls?: boolean
  sni?: string
  fingerprint?: string
  'skip-cert-verify'?: boolean
  headers?: Record<string, string>
}

export interface Socks5 extends ProxyBase {
  type: 'socks5'
  port: number
  username?: string
  password?: string
  tls?: boolean
  fingerprint?: string
  'skip-cert-verify'?: boolean
  udp?: boolean
}

export interface SSBase extends ProxyBase {
  type: 'ss'
  port: number
  cipher: string
  password: string
  'udp-over-tcp'?: boolean
  'udp-over-tcp-version'?: number
  udp?: boolean
}

export interface ObfsPlugin {
  plugin: 'obfs'
  'plugin-opts': {
    mode: string
    host?: string
  }
}

export interface V2rayPlugin {
  plugin: 'v2ray-plugin'
  'plugin-opts': {
    mode: string
    host?: string
    path?: string
    tls?: boolean
    fingerprint?: string
    'skip-cert-verify'?: boolean
    headers?: Record<string, string>
    mux?: boolean
    'v2ray-http-upgrade'?: boolean
    'v2ray-http-upgrade-fast-open'?: boolean
  }
}

export interface ShadowTlsPlugin {
  plugin: 'shadow-tls'
  'client-fingerprint'?: string
  'plugin-opts': {
    host: string
    password: string
    version?: number
    fingerprint?: string
    'skip-cert-verify'?: boolean
  }
}

export interface RestlsPlugin {
  plugin: 'restls'
  'client-fingerprint'?: string
  'plugin-opts': {
    host: string
    password: string
    'version-hint': string
    'restls-script'?: string
  }
}

export type SS = SSBase & (Empty | ObfsPlugin | V2rayPlugin | ShadowTlsPlugin | RestlsPlugin)

export interface SSR extends ProxyBase {
  type: 'ssr'
  port: number
  cipher: string
  password: string
  obfs: string
  protocol: string
  'obfs-param'?: string
  'protocol-param'?: string
  udp?: boolean
}

export type PortOrPortRange = { port: number } | { 'port-range': string }

interface MieruBase extends ProxyBase {
  type: 'mieru'
  username: string
  password: string
  transport: string
  multiplexing?: string
}

export type Mieru = MieruBase & PortOrPortRange

export interface Snell extends ProxyBase {
  type: 'snell'
  port: number
  psk: string
  version?: number
  'obfs-opts'?: Record<string, string>
  udp?: boolean
}

export interface VMessBase extends ProxyBase {
  type: 'vmess'
  port: number
  uuid: string
  alterId: number
  cipher: string
  'packet-encoding'?: string
  'global-padding'?: boolean
  'authenticated-length'?: boolean
  tls?: boolean
  servername?: string
  fingerprint?: string
  'client-fingerprint'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  udp?: boolean
}

export interface VLESSBase extends ProxyBase {
  type: 'vless'
  port: number
  uuid: string
  flow?: string
  'packet-encoding'?: string
  tls?: boolean
  servername?: string
  fingerprint?: string
  'client-fingerprint'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  udp?: boolean
}

export interface TrojanBase extends ProxyBase {
  type: 'trojan'
  port: number
  password: string
  sni?: string
  fingerprint?: string
  'client-fingerprint'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  'ss-opts'?: {
    enabled: true
    method?: string
    password: string
  }
  udp?: boolean
}

export interface WSNetwork {
  network: 'ws'
  'ws-opts'?: {
    path?: string
    headers?: Record<string, string>
    'max-early-data'?: number
    'early-data-header-name'?: string
    'v2ray-http-upgrade'?: boolean
    'v2ray-http-upgrade-fast-open'?: boolean
  }
}

export interface GRPCNetwork {
  network: 'grpc'
  'grpc-opts'?: {
    'grpc-service-name': string
  }
}

export interface HTTPNetwork {
  network: 'http'
  'http-opts'?: {
    method?: string
    path?: string[]
    headers?: Record<string, string[]>
  }
}

export interface H2Network {
  network: 'h2'
  'h2-opts'?: {
    path?: string
    host?: string[]
  }
}

export interface Reality {
  'reality-opts': {
    'public-key': string
    'short-id': string
  }
}

export type VMess = VMessBase & (Empty | WSNetwork | GRPCNetwork | HTTPNetwork | H2Network) & (Empty | Reality)

export type VLESS = VLESSBase & (Empty | WSNetwork | GRPCNetwork | HTTPNetwork | H2Network) & (Empty | Reality)

export type Trojan = TrojanBase & (Empty | WSNetwork | GRPCNetwork) & (Empty | Reality)

export type PortOrPorts = { port: number; ports?: string } | { port?: number; ports: string }

interface HysteriaBase extends ProxyBase {
  type: 'hysteria'
  'auth-str'?: string
  'hop-interval'?: number
  up: string
  down: string
  obfs?: string
  protocol?: string
  sni?: string
  fingerprint?: string
  'ca-str'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  'recv-window-conn'?: number
  'recv-window'?: number
  'disable-mtu-discovery'?: boolean
  'fast-open'?: boolean
}

export type Hysteria = HysteriaBase & PortOrPorts

interface Hysteria2Base extends ProxyBase {
  type: 'hysteria2'
  port?: number
  ports?: string
  password: string
  'hop-interval'?: number
  up?: string
  down?: string
  obfs?: string
  'obfs-password'?: string
  sni?: string
  fingerprint?: string
  'ca-str'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  'cwnd'?: number
  'udp-mtu'?: number
}

export type Hysteria2 = Hysteria2Base & PortOrPorts

export interface TUIC extends ProxyBase {
  type: 'tuic'
  port: number
  token?: string
  uuid?: string
  password?: string
  ip?: string
  'congestion-controller'?: string
  'udp-relay-mode'?: string
  sni?: string
  fingerprint?: string
  'ca-str'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  'max-udp-relay-packet-size'?: number
  'heartbeat-interval'?: number
  'request-timeout'?: number
  'max-open-streams'?: number
  cwnd?: number
  'recv-window-conn'?: number
  'recv-window'?: number
  'max-datagram-frame-size'?: number
  'udp-over-stream-version'?: number
  'reduce-rtt'?: boolean
  'fast-open'?: boolean
  'disable-mtu-discovery'?: boolean
  'udp-over-stream'?: boolean
  'disable-sni'?: boolean
}

export interface WireGuard extends ProxyBase {
  type: 'wireguard'
  port: number
  'private-key': string
  'public-key'?: string
  'pre-shared-key'?: string
  ip?: string
  ipv6?: string
  reserved?: number[]
  'allowed-ips'?: string[]
  workers?: number
  mtu?: number
  'persistent-keepalive'?: number
  'refresh-server-ip-interval'?: number
  'amnezia-wg-option'?: {
    jc: number
    jmin: number
    jmax: number
    s1: number
    s2: number
    h1: number
    h2: number
    h4: number
    h3: number
  }
  // peers?: {
  //   server: string
  //   port: number
  //   'public-key'?: string
  //   'pre-shared-key'?: string
  //   reserved?: number[]
  //   'allowed-ips'?: string[]
  // }[]
  'remote-dns-resolve'?: boolean
  dns?: string[]
  udp?: boolean
}

export interface SSH extends ProxyBase {
  type: 'ssh'
  port: number
  username: string
  password?: string
  'private-key'?: string
  'private-key-passphrase'?: string
  'host-key'?: string[]
  'host-key-algorithms'?: string[]
}

export interface AnyTLS extends ProxyBase {
  type: 'anytls'
  port: number
  password: string
  sni?: string
  fingerprint?: string
  'client-fingerprint'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  udp?: boolean
  'idle-session-check-interval'?: number
  'idle-session-timeout'?: number
  'min-idle-session'?: number
}

export type Proxy =
  | HTTP
  | Socks5
  | SS
  | SSR
  | Mieru
  | Snell
  | VMess
  | VLESS
  | Trojan
  | Hysteria
  | Hysteria2
  | TUIC
  | WireGuard
  | SSH
  | AnyTLS
