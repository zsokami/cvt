import * as esbuild from 'https://deno.land/x/esbuild@v0.24.2/mod.js'

export async function build(input: string, output: string) {
  await esbuild.build({
    entryPoints: [input],
    outfile: output,
    bundle: true,
    format: 'esm',
    charset: 'utf8',
    plugins: [{
      name: 'http',
      setup(build) {
        build.onResolve({ filter: /^https?:\/\// }, ({ path }) => ({
          path,
          namespace: 'http',
        }))
        build.onResolve({ filter: /.*/, namespace: 'http' }, ({ path, importer }) => ({
          path: new URL(path, importer).toString(),
          namespace: 'http',
        }))
        build.onLoad({ filter: /.*/, namespace: 'http' }, async ({ path }) => {
          const { code } = await esbuild.transform(await (await fetch(path)).text(), { loader: 'ts' })
          return { contents: code }
        })
      },
    }],
  })
  await esbuild.stop()
}
