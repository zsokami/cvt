async function load() {
  const dv = new DataView(
    await (await fetch('https://raw.githubusercontent.com/zsokami/cvt/main/geoip.dat')).arrayBuffer(),
  )
  const code2flag = new Map<number, string>()
  for (let i = 65; i < 91; i++) {
    for (let j = 65; j < 91; j++) {
      code2flag.set(i * 256 + j, String.fromCharCode(55356, 56741 + i, 55356, 56741 + j))
    }
  }
  const starts: number[] = []
  const flags: string[] = []
  flags.length = dv.byteLength / 6
  starts.length = flags.length + 1
  for (let i = 0, j = 0; i < dv.byteLength; i += 6, j++) {
    starts[j] = dv.getUint32(i)
    flags[j] = code2flag.get(dv.getUint16(i + 4)) ?? ''
  }
  starts[flags.length] = 2 ** 32
  return { starts, flags }
}

function ipv4ToNumber(ip: string) {
  const match = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
  if (!match) return -1
  const parts = match.slice(1).map(Number)
  if (!parts.every((x) => 0 <= x && x < 256)) return -1
  return parts.reduce((a, b) => a * 256 + b)
}

let loaded: ReturnType<typeof load> | undefined

export async function geoip(ip: string): Promise<string> {
  const num = ipv4ToNumber(ip)
  if (num === -1) return ''
  loaded ??= load().catch(() => {
    loaded = undefined
    return { starts: [0, 2 ** 32], flags: [''] }
  })
  const { starts, flags } = await loaded
  let lo = 0, hi = flags.length
  for (;;) {
    const mid = (lo + hi) >>> 1
    if (num < starts[mid]) {
      hi = mid
    } else if (num >= starts[mid + 1]) {
      lo = mid + 1
    } else {
      return flags[mid]
    }
  }
}
