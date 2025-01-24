import handler from '../netlify/edge-functions/main/main.ts'

Deno.serve({ port: parseInt(Deno.args[0]) || undefined }, handler)
