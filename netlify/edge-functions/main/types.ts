export type None<T> = { [K in keyof T]?: never }
export type Option<T> = T | None<T>

export interface ProxyBase {
  name: string
  server: string
  tfo?: boolean
  mptcp?: boolean
  'ip-version'?: string
  'interface-name'?: string
  'routing-mark'?: number
  'dialer-proxy'?: string
  hidden?: boolean // 在 proxy-groups 中隐藏该节点，在 proxies 中仍保留
}

export interface HTTP extends ProxyBase {
  type: 'http'
  port: number
  username?: string
  password?: string
  tls?: boolean
  sni?: string
  fingerprint?: string
  certificate?: string
  'private-key'?: string
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
  certificate?: string
  'private-key'?: string
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
    certificate?: string
    'private-key'?: string
    'skip-cert-verify'?: boolean
    headers?: Record<string, string>
    mux?: boolean
    'v2ray-http-upgrade'?: boolean
    'v2ray-http-upgrade-fast-open'?: boolean
  } & Option<ECH>
}

export interface GostPlugin {
  plugin: 'gost-plugin'
  'plugin-opts': {
    mode: string
    host?: string
    path?: string
    tls?: boolean
    fingerprint?: string
    certificate?: string
    'private-key'?: string
    'skip-cert-verify'?: boolean
    headers?: Record<string, string>
    mux?: boolean
  } & Option<ECH>
}

export interface ShadowTlsPlugin {
  plugin: 'shadow-tls'
  'client-fingerprint'?: string
  'plugin-opts': {
    host: string
    password?: string
    version?: number
    fingerprint?: string
    certificate?: string
    'private-key'?: string
    alpn?: string[]
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

export interface KcpTunPlugin {
  plugin: 'kcptun'
  'plugin-opts': {
    key?: string
    crypt?: string
    mode?: string
    conn?: number
    autoexpire?: number
    scavengettl?: number
    mtu?: number
    ratelimit?: number
    sndwnd?: number
    rcvwnd?: number
    datashard?: number
    parityshard?: number
    dscp?: number
    nocomp?: boolean
    acknodelay?: boolean
    nodelay?: number
    interval?: number
    resend?: number
    nc?: number
    sockbuf?: number
    smuxver?: number
    smuxbuf?: number
    framesize?: number
    streambuf?: number
    keepalive?: number
  }
}

export type SS = SSBase & Option<ObfsPlugin | V2rayPlugin | GostPlugin | ShadowTlsPlugin | RestlsPlugin | KcpTunPlugin>

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

export type PortOrPortRange = { port: number | string } | { 'port-range': string }

interface MieruBase extends ProxyBase {
  type: 'mieru'
  username: string
  password: string
  transport: string
  multiplexing?: string
  'handshake-mode'?: string
  udp?: boolean
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
  certificate?: string
  'private-key'?: string
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
  encryption?: string
  tls?: boolean
  servername?: string
  fingerprint?: string
  certificate?: string
  'private-key'?: string
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
  certificate?: string
  'private-key'?: string
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
    'grpc-service-name'?: string
    'grpc-user-agent'?: string
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
    'support-x25519mlkem768'?: boolean
  }
}

export interface ECH {
  'ech-opts': {
    enable?: boolean
    config?: string
  }
}

export type VMess =
  & VMessBase
  & Option<WSNetwork | GRPCNetwork | HTTPNetwork | H2Network>
  & Option<Reality>
  & Option<ECH>

export type VLESS =
  & VLESSBase
  & Option<WSNetwork | GRPCNetwork | HTTPNetwork | H2Network>
  & Option<Reality>
  & Option<ECH>

export type Trojan =
  & TrojanBase
  & Option<WSNetwork | GRPCNetwork>
  & Option<Reality>
  & Option<ECH>

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
  certificate?: string
  'private-key'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  'recv-window-conn'?: number
  'recv-window'?: number
  'disable-mtu-discovery'?: boolean
  'fast-open'?: boolean
}

export type Hysteria = HysteriaBase & PortOrPorts & Option<ECH>

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
  certificate?: string
  'private-key'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  'cwnd'?: number
  'udp-mtu'?: number
  'initial-stream-receive-window'?: number
  'max-stream-receive-window'?: number
  'initial-connection-receive-window'?: number
  'max-connection-receive-window'?: number
}

export type Hysteria2 = Hysteria2Base & PortOrPorts & Option<ECH>

export interface TUICBase extends ProxyBase {
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
  certificate?: string
  'private-key'?: string
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

export type TUIC = TUICBase & Option<ECH>

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
    jc?: number
    jmin?: number
    jmax?: number
    s1?: number
    s2?: number
    s3?: number
    s4?: number
    h1?: string
    h2?: string
    h3?: string
    h4?: string
    i1?: string
    i2?: string
    i3?: string
    i4?: string
    i5?: string
    j1?: string
    j2?: string
    j3?: string
    itime?: number
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

export interface AnyTLSBase extends ProxyBase {
  type: 'anytls'
  port: number
  password: string
  sni?: string
  fingerprint?: string
  certificate?: string
  'private-key'?: string
  'client-fingerprint'?: string
  alpn?: string[]
  'skip-cert-verify'?: boolean
  udp?: boolean
  'idle-session-check-interval'?: number
  'idle-session-timeout'?: number
  'min-idle-session'?: number
}

export type AnyTLS = AnyTLSBase & Option<ECH>

export interface Sudoku extends ProxyBase {
  type: 'sudoku'
  port: number
  key: string
  'aead-method'?: string
  'table-type'?: string
  'custom-table'?: string
  'custom-tables'?: string[]
  'padding-min'?: number
  'padding-max'?: number
  'enable-pure-downlink'?: boolean
  'http-mask'?: boolean
  'http-mask-mode'?: string
  'http-mask-tls'?: boolean
  'http-mask-host'?: string
  'path-root'?: string
  'http-mask-multiplex'?: string
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
  | Sudoku
