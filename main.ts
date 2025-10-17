import handler from './netlify/edge-functions/main/main.ts'
import { splitRight } from './netlify/edge-functions/main/utils.ts'

let hostname = Deno.env.get('HOST') || Deno.env.get('IP')
let port = Number(Deno.env.get('PORT')) || undefined

if (Deno.args[0]) {
  const [a, b] = splitRight(Deno.args[0], ':')
  if (b) {
    hostname = a
    port = parseInt(b)
  } else {
    port = parseInt(a)
  }
}

Deno.serve({ hostname, port }, handler)
