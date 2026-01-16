import { decodeBase64, encodeBase64 } from 'https://raw.githubusercontent.com/denoland/std/main/encoding/base64.ts'
export { encodeBase64 }
export { encodeBase64Url } from 'https://raw.githubusercontent.com/denoland/std/main/encoding/base64url.ts'
export { parse as parseYAML } from 'https://raw.githubusercontent.com/denoland/std/main/yaml/parse.ts'

const textDecoder = new TextDecoder()

export function decodeBase64Url(b64url: string): string {
  b64url = b64url.replaceAll(/#.*|\s+/g, '').replaceAll('%2B', '+').replaceAll('%2F', '/').replaceAll('%3D', '=')
  if (b64url.length % 4 === 1) {
    throw new TypeError('Failed to decode base64url: b64url’s length divides by 4 leaving a remainder of 1')
  }
  if (!/^[-_+/A-Za-z0-9]*={0,2}$/.test(b64url)) {
    throw new TypeError('Failed to decode base64url: invalid character')
  }
  return textDecoder.decode(decodeBase64(b64url.replaceAll('-', '+').replaceAll('_', '/')))
}

export const urlDecode = (x: string | null | undefined): string => {
  x ??= ''
  try {
    x = decodeURIComponent(x)
  } catch {
    // pass
  }
  return x
}
export const urlDecodePlus = (x: string | null | undefined): string => urlDecode(x?.replaceAll('+', ' '))

export function pickTruthy<T, K>(o: T, ...keys: K[]): Partial<Pick<T, K & keyof T>> {
  const r = {}
  if (!o) return r
  for (const k of keys) {
    // @ts-ignore:
    const v = o[k]
    // @ts-ignore:
    if (v) r[k] = v
  }
  return r
}

export function pickNonEmptyString<T, K>(o: T, ...keys: (K | [K, string])[]): Partial<Record<K & keyof T, string>> {
  const r = {}
  if (!o) return r
  for (const x of keys) {
    const [k, defaultValue] = Array.isArray(x) ? x : [x, undefined]
    // @ts-ignore:
    const v = o[k]
    // @ts-ignore:
    if (v != null && v !== '') r[k] = String(v)
    // @ts-ignore:
    else if (defaultValue) r[k] = defaultValue
  }
  return r
}

export function pickNumber<T, K>(o: T, ...keys: K[]): Partial<Record<K & keyof T, number>> {
  const r = {}
  if (!o) return r
  for (const k of keys) {
    // @ts-ignore:
    const v = o[k]
    if (v != null && v !== '') {
      const n = Number(v)
      // @ts-ignore:
      if (!isNaN(n)) r[k] = n
    }
  }
  return r
}

export function pickTrue<T, K>(o: T, ...keys: K[]): Partial<Record<K & keyof T, true>> {
  const r = {}
  if (!o) return r
  for (const k of keys) {
    // @ts-ignore:
    const v = o[k]
    // @ts-ignore:
    if (v) r[k] = true
  }
  return r
}

export function splitLeft(str: string, separator: string, maxSplit = 1): string[] {
  const result: string[] = []
  let i = 0
  while (maxSplit-- > 0) {
    const j = str.indexOf(separator, i)
    if (j < 0) break
    result.push(str.slice(i, j))
    i = j + separator.length
  }
  result.push(str.slice(i))
  return result
}

export function splitRight(str: string, separator: string, maxSplit = 1): string[] {
  const result: string[] = []
  let i = str.length
  while (maxSplit-- > 0) {
    if (i <= 0) break
    const j = str.lastIndexOf(separator, i - 1)
    if (j < 0) break
    result.push(str.slice(j + separator.length, i))
    i = j
  }
  result.push(str.slice(0, i))
  return result.reverse()
}

export function createPure<T extends Record<PropertyKey, unknown>>(o: T): T {
  return Object.assign(Object.create(null), o)
}

const F = new Set(['0', 'f', 'false', 'n', 'no', 'off'])
const T = new Set(['1', 't', 'true', 'y', 'yes', 'on'])

export function parseBool(value: unknown): boolean | undefined {
  if (value == null) return undefined
  if (typeof value === 'string') {
    const lower = value.trim().toLowerCase()
    if (F.has(lower)) return false
    if (T.has(lower)) return true
    return undefined
  }
  if (typeof value === 'boolean') return value
  if (typeof value === 'number' || typeof value === 'bigint') return Boolean(value)
  if (typeof value === 'object') {
    if ('valueOf' in value) {
      const v = value.valueOf()
      if (typeof v !== 'object') return parseBool(v)
    }
    if ('length' in value && (typeof value.length === 'number' || typeof value.length === 'bigint')) {
      return Boolean(value.length)
    }
    if ('size' in value && (typeof value.size === 'number' || typeof value.size === 'bigint')) {
      return Boolean(value.size)
    }
    return parseBool(String(value))
  }
  return undefined
}
