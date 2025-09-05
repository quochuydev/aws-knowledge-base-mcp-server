import Anthropic from "@anthropic-ai/sdk";

export function createAnthropicService(apiKey: string) {
  const client = new Anthropic({ apiKey });

  async function generateAnswer(
    systemPrompt: string,
    userPrompt: string
  ): Promise<string> {
    const response = await client.messages.create({
      model: "claude-3-5-sonnet-20240620",
      system: systemPrompt,
      messages: [
        {
          role: "user",
          content: userPrompt,
        },
      ],
      max_tokens: 1024,
    });

    return response.content.find((c) => c.type === "text")?.text ?? "";
  }

  async function embed(text: string): Promise<number[]> {
    throw new Error("Anthropic API does not provide embeddings yet.");
  }

  return { generateAnswer, embed };
}
