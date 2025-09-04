import { config } from "dotenv";
import { retrieve } from "./services/retrieve";

config();

async function main() {
  const env = process.env as Record<string, string>;

  const query = "What is in the docs?";

  const { answer, sources } = await retrieve(env, query);

  console.log(`Answer: ${answer}\nSources:\n`, sources.length);
}

main().catch(console.error);
