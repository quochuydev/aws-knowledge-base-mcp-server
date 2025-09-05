import OpenAI from "openai";
import { encodingForModel } from "js-tiktoken";

export function createOpenAIService(apiKey: string) {
  const client = new OpenAI({ apiKey });

  async function generateAnswer(
    systemPrompt: string,
    userPrompt: string
  ): Promise<string> {
    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: systemPrompt,
        },
        {
          role: "user",
          content: userPrompt,
        },
      ],
    });

    return response.choices[0]?.message?.content ?? "";
  }

  async function embed(text: string): Promise<number[]> {
    const embedding = await client.embeddings.create({
      model: "text-embedding-3-small",
      input: text,
    });
    return embedding.data[0].embedding;
  }

  function calculateCost(
    text: string,
    messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[],
    answer: string
  ): {
    embeddingCost: number;
    completionCost: number;
    totalCost: number;
  } {
    const encEmbed = encodingForModel("text-embedding-3-small");
    const encChat = encodingForModel("gpt-4o-mini");

    const embeddingTokens = encEmbed.encode(text).length;
    const embeddingCost = (embeddingTokens / 1000) * 0.00002;

    const inputTokens = messages
      .map((m) => encChat.encode(m.content as string).length)
      .reduce((a, b) => a + b, 0);

    const outputTokens = encChat.encode(answer).length;
    const completionCost = inputTokens * 0.00000015 + outputTokens * 0.0000006;
    const totalCost = embeddingCost + completionCost;

    return {
      embeddingCost,
      completionCost,
      totalCost,
    };
  }

  return { generateAnswer, embed, calculateCost };
}
