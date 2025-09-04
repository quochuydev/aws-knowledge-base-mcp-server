import { QdrantClient } from "@qdrant/js-client-rest";

export function createQdrantService(params: {
  url: string;
  apiKey: string;
  collection: string;
}) {
  const { url, apiKey, collection } = params;

  const client = new QdrantClient({ url, apiKey });

  async function search(vector: number[], limit = 5) {
    return client.search(collection, { vector, limit });
  }

  async function upsert(points: { id: string; vector: number[] }[]) {
    return client.upsert(collection, { points });
  }

  return { search, upsert };
}
