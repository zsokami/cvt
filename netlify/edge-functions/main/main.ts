import { cvt } from './cvt.ts'
import { parseBool, pickTruthy, urlDecode } from './utils.ts'
import { VERSION } from './version.ts'

async function main(req: Request) {
  const reqURL = new URL(req.url)
  if (reqURL.pathname === '/version') {
    return new Response(VERSION)
  }
  const args_match = reqURL.pathname.match(/^\/!([^/]*)/)
  let args: Record<string, string | undefined> = {}
  let to = 'clash'
  if (args_match) {
    reqURL.pathname = reqURL.pathname.slice(args_match[0].length)
    args = Object.fromEntries(new URLSearchParams(args_match[1]))
    if ('auto' in args) to = 'auto'
    else if ('base64' in args) to = 'base64'
    else if ('uri' in args) to = 'uri'
    else if ('clash-proxies' in args) to = 'clash-proxies'
    else to = args['to'] || 'clash'
  }
  let from
  if (reqURL.pathname.match(/^\/(?:https?|data):/i)) {
    from = reqURL.pathname.slice(1) + reqURL.search
  } else {
    from = urlDecode(reqURL.pathname.slice(1))
  }

  const [result, counts, _headers] = await cvt(
    from,
    to,
    {
      ua: args['ua'] || req.headers.get('user-agent') || undefined,
      ndl: 'ndl' in args,
      filter: args['filter'],
      hide: args['hide'],
      meta: parseBool(args['meta']),
      proxy: args['proxy'],
    },
  )

  const headers: Record<string, string> = {
    ...counts[2] && { 'x-count': counts.join('/') },
  }
  if (!result && !_headers?.has('subscription-userinfo')) {
    return new Response('Not Found', { status: 404, headers })
  }
  if (result.startsWith('订阅转换失败')) {
    return new Response(result, { status: 400, headers })
  }
  if (_headers) {
    const subinfo = _headers.get('subscription-userinfo')
    if (subinfo) {
      headers['subscription-userinfo'] = subinfo.replaceAll(/(?<==)[^;]+/g, (value) => {
        value = value.trim()
        if (!value) return ''
        const m = value.match(/^(\d+)(?:\.\d*)?$/)
        if (!m) return '0'
        return m[1]
      })
    }
    Object.assign(
      headers,
      pickTruthy(
        Object.fromEntries(_headers),
        'profile-update-interval',
        'profile-web-page-url',
      ),
    )
  }
  if (!req.headers.get('accept')?.includes('text/html')) {
    let m, name, disposition
    if ((name = args['filename'])) {
      // pass
    } else if ((disposition = _headers?.get('content-disposition'))) {
      headers['content-disposition'] = disposition
    } else if ((m = from.match(/^https?:\/\/raw\.githubusercontent\.com\/+([^/|]+)(?:\/+[^/|]+){2,}\/+([^/|]+)$/))) {
      name = m[1] === m[2] ? m[1] : m[1] + ' - ' + urlDecode(m[2])
    } else if (
      (m = from.match(
        /^(https?:\/\/raw\.githubusercontent\.com\/+([^/|]+))(?:\/+[^/|]+){3,}(?:\|+\1(?:\/+[^/|]+){3,})*$/,
      ))
    ) {
      name = m[2]
    } else if ((m = from.match(/^(https?:\/\/gist\.githubusercontent\.com\/+([^/|]+))\/[^|]+(?:\|+\1\/[^|]+)*$/))) {
      name = m[2] + ' - gist'
    }
    if (name) {
      headers['content-disposition'] = `attachment; filename*=UTF-8''${encodeURIComponent(name)}`
    }
  }
  return new Response(result, { headers })
}

export default async (req: Request) => {
  try {
    return await main(req)
  } catch (e) {
    return new Response(String(e), { status: 500 })
  }
}

export const config = {
  path: '/*',
}
