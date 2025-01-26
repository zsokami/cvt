import * as esbuild from 'https://deno.land/x/esbuild@v0.24.2/mod.js'

export async function build(
  input: string | string[] | Record<string, string> | { in: string; out: string }[],
  outfile_or_options: string | esbuild.BuildOptions,
) {
  await esbuild.build({
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
    ...typeof input === 'string' ? { stdin: { contents: input, resolveDir: '.' } } : { entryPoints: input },
    ...typeof outfile_or_options === 'string' ? { outfile: outfile_or_options } : outfile_or_options,
  })
  await esbuild.stop()
}
