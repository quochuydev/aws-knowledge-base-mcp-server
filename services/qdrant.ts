import { QdrantClient } from "@qdrant/js-client-rest";

export function createQdrantService(params: { url: string; apiKey: string }) {
  const { url, apiKey } = params;

  const client = new QdrantClient({ url, apiKey });

  async function searchDocs(vector: number[], limit = 5) {
    return client.search("docs", { vector, limit });
  }

  return { searchDocs };
}
