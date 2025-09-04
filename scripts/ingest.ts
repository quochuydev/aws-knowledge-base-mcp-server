import fs from "fs";
import path from "path";
import OpenAI from "openai";
import { QdrantClient } from "@qdrant/js-client-rest";
import { config } from "dotenv";

config();

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const qdrant = new QdrantClient({
  url: process.env.QDRANT_URL!,
  apiKey: process.env.QDRANT_API_KEY,
});

async function ingest() {
  const filesDir = path.resolve("./files");
  const files = fs.readdirSync(filesDir).filter((f) => f.endsWith(".md"));

  for (const file of files) {
    const content = fs.readFileSync(path.join(filesDir, file), "utf-8");
    const chunks = content.split(/\n\s*\n/).filter(Boolean);

    console.log(`Processing ${file}, ${chunks.length} chunks`);

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];

      const embeddingResp = await openai.embeddings.create({
        model: "text-embedding-3-small",
        input: chunk,
      });

      const vector = embeddingResp.data[0].embedding;

      await qdrant.upsert("docs", {
        points: [
          {
            id: `${file}-${i}`,
            vector,
            payload: { text: chunk, source: file },
          },
        ],
      });
    }
  }

  console.log("✅ Ingestion complete!");
}

ingest().catch((err) => {
  console.error(err);
  process.exit(1);
});
