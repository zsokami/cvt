import { build } from './esbuild.ts'

await build('scripts/middleware.ts', '.vercel/output/functions/_middleware.func/index.js')

Deno.writeTextFileSync(
  '.vercel/output/functions/_middleware.func/.vc-config.json',
  '{"runtime":"edge","entrypoint":"index.js"}',
)
Deno.writeTextFileSync(
  '.vercel/output/config.json',
  '{"version":3,"routes":[{"src":"/(.*)","middlewarePath":"_middleware"}]}',
)
