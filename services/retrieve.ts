import OpenAI from "openai";
import { QdrantClient } from "@qdrant/js-client-rest";

export async function retrieve(env: Record<string, string>, text: string) {
  // 1. Init clients
  const openai = new OpenAI({ apiKey: env.OPENAI_API_KEY });
  const qdrant = new QdrantClient({
    url: env.QDRANT_URL,
    apiKey: env.QDRANT_API_KEY,
  });

  // 2. Create embedding for the query
  const embeddingResp = await openai.embeddings.create({
    model: "text-embedding-3-small",
    input: text,
  });
  const vector = embeddingResp.data[0].embedding;

  // 3. Search in Qdrant
  const results = await qdrant.search("docs", {
    vector,
    limit: 5,
  });

  // 4. Build context from search results
  const context = results.map((r) => r.payload?.text ?? "").join("\n---\n");

  // 5. Ask OpenAI with context
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "system",
        content:
          "You are a helpful assistant. Answer using the provided context if relevant.",
      },
      {
        role: "user",
        content: `Context:\n${context}\n\nQuestion: ${text}`,
      },
    ],
  });

  return {
    answer: completion.choices[0]?.message?.content ?? "",
    sources: results,
  };
}
