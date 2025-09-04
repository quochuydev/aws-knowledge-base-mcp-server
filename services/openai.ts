import OpenAI from "openai";

export function createOpenAIService(apiKey: string) {
  const client = new OpenAI({ apiKey });

  async function generateAnswer(prompt: string): Promise<string> {
    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "user",
          content: prompt,
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

  return { generateAnswer, embed };
}
