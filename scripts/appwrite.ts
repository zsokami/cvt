import handler from '../netlify/edge-functions/main/main.ts'

export default async ({ req, res }: {
  req: { url: string; method: string; headers: Record<string, string>; bodyBinary: ArrayBuffer }
  res: { binary: (body: ArrayBuffer, statusCode: number, headers: Record<string, string>) => unknown }
}) => {
  const resp = await handler(
    new Request(req.url, {
      method: req.method,
      headers: req.headers,
      ...req.bodyBinary.byteLength && { body: req.bodyBinary },
    }),
  )
  return res.binary(await resp.arrayBuffer(), resp.status, Object.fromEntries(resp.headers))
}
