import { build } from './esbuild.ts'

await build('scripts/worker.ts', 'scripts/__worker.js')
