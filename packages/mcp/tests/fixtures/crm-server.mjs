/**
 * A small MCP server built with the official SDK, holding synthetic customer
 * data. Imported by the tests, or run over stdio with `--stdio`
 * (`--noisy` also writes a line that is not JSON-RPC to stdout first).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

/** Requests the server received, for the tests to inspect. */
export const received = [];

export function createCrmServer() {
  const server = new McpServer({ name: "crm", version: "1.0.0" });

  server.registerTool(
    "find_customer",
    { description: "Find a customer by id.", inputSchema: { id: z.string() } },
    async ({ id }) => ({
      content: [{ type: "text", text: `Customer ${id}: ada@example.com, phone 555-867-5309` }],
    }),
  );

  server.registerTool(
    "send_mail",
    {
      description: "Send an e-mail.",
      inputSchema: { to: z.string(), body: z.string() },
    },
    async ({ to, body }) => {
      received.push({ tool: "send_mail", to, body });
      return {
        content: [{ type: "text", text: `delivered: ${String(to === "ada@example.com")}` }],
      };
    },
  );

  server.registerTool(
    "profile",
    {
      description: "Structured profile.",
      inputSchema: { id: z.string() },
      outputSchema: { id: z.string(), email: z.string() },
    },
    async ({ id }) => ({
      content: [{ type: "text", text: JSON.stringify({ id, email: "ada@example.com" }) }],
      structuredContent: { id, email: "ada@example.com" },
    }),
  );

  server.registerTool(
    "deep",
    { description: "A result nested too deeply to inspect.", inputSchema: {} },
    async () => {
      let nested = { email: "ada@example.com" };
      for (let i = 0; i < 600; i++) nested = { nested };
      return { content: [{ type: "text", text: "deep" }], structuredContent: nested };
    },
  );

  server.registerResource(
    "customer",
    "crm://customers/42",
    { mimeType: "text/plain", description: "A customer record." },
    async (uri) => ({ contents: [{ uri: uri.href, text: "Owner: ada@example.com" }] }),
  );

  server.registerPrompt(
    "follow_up",
    { description: "Follow up with a customer.", argsSchema: { email: z.string() } },
    ({ email }) => {
      received.push({ prompt: "follow_up", email });
      return {
        messages: [{ role: "user", content: { type: "text", text: `Write to ${email}.` } }],
      };
    },
  );

  return server;
}

if (process.argv.includes("--stdio")) {
  if (process.argv.includes("--noisy")) process.stdout.write("starting for ada@example.com\n");
  await createCrmServer().connect(new StdioServerTransport());
}
