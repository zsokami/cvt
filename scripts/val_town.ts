import { ValTown } from 'jsr:@valtown/sdk'

const repo = Deno.env.get('GITHUB_REPOSITORY')
const sha = Deno.env.get('GITHUB_SHA')

const client = new ValTown()

await client.vals.files.update('1b48ceac-4c01-11f0-836c-76b3cceeab13', {
  path: 'main.ts',
  content:
    `export { default } from "https://raw.githubusercontent.com/${repo}/${sha}/netlify/edge-functions/main/main.ts";`,
})
