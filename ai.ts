import { config } from "dotenv";
import { createAnthropicService } from "./services/anthropic";
import { createOpenAIService } from "./services/openai";
import { createQdrantService } from "./services/qdrant";

config();

export const retrieve = async (query: string) => {
  const env = process.env as Record<string, string>;

  const openaiService = createOpenAIService(env.OPENAI_API_KEY);

  const anthropicService = createAnthropicService(env.ANTHROPIC_API_KEY);

  const qdrantService = createQdrantService({
    url: env.QDRANT_URL,
    apiKey: env.QDRANT_API_KEY,
  });

  const vector = await openaiService.embed(query);
  const sources = await qdrantService.searchDocs(vector);

  const context = sources.map((r) => r.payload?.text ?? "").join("\n---\n");

  const answer = await anthropicService.generateAnswer(
    "You are a helpful assistant. Answer using the provided context if relevant.",
    `Context:${context}\n\nQuestion: ${query}`
  );

  console.log(`Answer: ${answer}`);
  console.log(`Sources: ${sources.length}`);

  return { answer };
};
