import { encodingForModel } from "js-tiktoken";
import OpenAI from "openai";

type CostBreakdown = {
  embeddingCost: number;
  completionCost: number;
  totalCost: number;
};

export function calculateCost(
  text: string,
  messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[],
  answer: string
): CostBreakdown {
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
