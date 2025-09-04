import { QdrantClient } from "@qdrant/js-client-rest";
import { config } from "dotenv";
import fs from "fs";
import OpenAI from "openai";
import path from "path";
import { v4 as uuidv4 } from "uuid";

config();

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const qdrant = new QdrantClient({
  url: process.env.QDRANT_URL!,
  apiKey: process.env.QDRANT_API_KEY,
});

async function ingest() {
  try {
    await qdrant.getCollection("docs");
  } catch (error: any) {
    console.log(`debug:error.message`, error.message);
    console.log(`debug:error.status`, error.status);

    if (error.status === 404) {
      await qdrant.createCollection("docs", {
        vectors: {
        size: 1536, // text-embedding-3-small
          distance: "Cosine",
        },
      });
    }
  }

  const filesDir = path.resolve("./files");
  const files = fs.readdirSync(filesDir).filter((f) => f.endsWith(".md"));

  for (const file of files) {
    const content = fs.readFileSync(path.join(filesDir, file), "utf-8");
    const chunks = content.split(/\n\s*\n/).filter(Boolean);

    console.log(`Processing ${file}, ${chunks.length} chunks`);

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const pointId = uuidv4();

      const embeddingResp = await openai.embeddings.create({
        model: "text-embedding-3-small",
        input: chunk,
      });

      const vector = embeddingResp.data[0].embedding;

      await qdrant.upsert("docs", {
        points: [
          {
            id: pointId,
            vector,
            payload: {
              text: chunk,
              source: file,
            },
          },
        ],
      });

      console.log(`upsert:pointId`, pointId);
    }
  }

  console.log("✅ Ingestion complete!");
}

ingest().catch((err) => {
  console.error(err);
  process.exit(1);
});
