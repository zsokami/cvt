import handler from '../netlify/edge-functions/main/main.ts'
import { splitRight } from '../netlify/edge-functions/main/utils.ts'

let hostname, port

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
