import type { Proxy } from './types.ts'
import { CIPHERS_OLD_CLASH_SUPPORTED, TYPES_OLD_CLASH_SUPPORTED } from './consts.ts'

export function requireOldClashSupport<T extends Readonly<Proxy>>(proxy: T): T {
  if (!TYPES_OLD_CLASH_SUPPORTED.has(proxy.type)) {
    throw Error(`Unsupported type: ${proxy.type}`)
  }
  if ((proxy.type === 'ss' || proxy.type === 'ssr')) {
    if (!CIPHERS_OLD_CLASH_SUPPORTED[proxy.type].has(proxy.cipher)) {
      throw Error(`Unsupported cipher: ${proxy.cipher}`)
    }
  } else if (proxy.type === 'vmess' || proxy.type === 'vless') {
    if (!/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(proxy.uuid)) {
      throw Error(`Unsupported uuid: ${proxy.uuid}`)
    }
  }
  return proxy
}
