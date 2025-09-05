import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import express, { Request, Response } from "express";
import morgan from "morgan";
import { z } from "zod";
import * as ai from "./ai";

const server = new McpServer({
  name: "aws-knowledge-base",
  version: "1.0.0",
});

server.tool(
  "search_knowledge_base",
  "Search for documentation of infrastructure and Model Context Protocol specification.",
  { query: z.string() },
  async ({ query }) => {
    const results = await ai.retrieve();

    const content: CallToolResult["content"] = [
      {
        type: "text",
        text: results.answer,
      },
    ];

    return { content };
  }
);

const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: undefined, // stateless mode
});

const app = express();
app.use(express.json());
app.use(morgan("common"));

app.post("/mcp", (req: Request, res: Response) =>
  transport.handleRequest(req, res, req.body)
);

const port = process.env.PORT || 8080;

server
  .connect(transport)
  .then(() => app.listen(port))
  .then(() => console.log(`App is listening at ${port}`))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

process.on("SIGINT", async () => {
  await transport.close().catch(console.error);
  await server.close().catch(console.error);
  process.exit(0);
});
