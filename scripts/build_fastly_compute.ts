import { build } from './esbuild.ts'

await build(
  `import handler from './netlify/edge-functions/main/main.ts'
addEventListener('fetch', (event) => event.respondWith(handler(event.request)))`,
  'scripts/__fastly_compute.js',
)
