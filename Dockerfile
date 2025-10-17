FROM denoland/deno

EXPOSE 8000

WORKDIR /app

COPY main.ts ./
COPY netlify/edge-functions/main/ netlify/edge-functions/main/

CMD ["run", "-A", "main.ts"]
