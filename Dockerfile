FROM denoland/deno

EXPOSE 8000

WORKDIR /app

COPY deno.json .
COPY scripts/server.ts scripts/
COPY netlify/edge-functions/main/ netlify/edge-functions/main/

CMD ["run", "-A", "scripts/server.ts"]
