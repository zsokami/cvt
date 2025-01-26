import { build } from './esbuild.ts'

await build(
  `import handler from './netlify/edge-functions/main/main.ts'
export default handler`,
  '.vercel/output/functions/_middleware.func/index.js',
)
Deno.writeTextFileSync(
  '.vercel/output/functions/_middleware.func/.vc-config.json',
  '{"runtime":"edge","entrypoint":"index.js"}',
)
Deno.writeTextFileSync(
  '.vercel/output/config.json',
  '{"version":3,"routes":[{"src":"/(.*)","middlewarePath":"_middleware"}]}',
)
