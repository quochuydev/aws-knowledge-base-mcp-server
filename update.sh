#!/bin/sh

set -e

# mkdir files

curl -o ./files/mcp.md https://modelcontextprotocol.io/llms-full.txt
# curl -o ./files/cloudflare.md https://developers.cloudflare.com/llms-full.txt
# curl -o ./files/pinecone.md https://docs.pinecone.io/llms-full.txt
curl -o ./files/vercel.md https://vercel.com/llms.txt

echo "Ingesting docs into Qdrant..."
npx tsx ./scripts/ingest.ts
