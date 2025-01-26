import { build } from './esbuild.ts'

await build(
  `import fetch from './netlify/edge-functions/main/main.ts'
export default { fetch }`,
  'scripts/__cloudflare_workers.js',
)
