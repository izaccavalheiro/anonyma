import { fileURLToPath } from "node:url";
import { PassThrough } from "node:stream";
import { createInterface } from "node:readline";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { guardMcpClient, runStdioProxy } from "../src/index.js";
// @ts-expect-error -- a JavaScript fixture without type declarations
import { createCrmServer, received } from "./fixtures/crm-server.mjs";

const fixture = fileURLToPath(new URL("./fixtures/crm-server.mjs", import.meta.url));

/** The text of the first content item of a tool result. */
function textOf(result: unknown): string | undefined {
  const content = (result as { content?: { text?: string }[] }).content;
  return content?.[0]?.text;
}

describe("@anonyma/mcp with the MCP SDK", () => {
  describe("guardMcpClient", () => {
    it("gives the caller tokens and the server real values", async () => {
      const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
      await (createCrmServer() as { connect(t: unknown): Promise<void> }).connect(serverSide);
      const client = guardMcpClient(new Client({ name: "test", version: "1.0.0" }));
      await client.connect(clientSide);

      const found = await client.callTool({ name: "find_customer", arguments: { id: "42" } });
      expect(textOf(found)).toBe("Customer 42: [EMAIL_0001], phone [PHONE_0001]");

      const sent = await client.callTool({
        name: "send_mail",
        arguments: { to: "[EMAIL_0001]", body: "Call [PHONE_0001]" },
      });
      expect(textOf(sent)).toBe("delivered: true");
      expect(received.at(-1)).toEqual({
        tool: "send_mail",
        to: "ada@example.com",
        body: "Call 555-867-5309",
      });

      const profile = await client.callTool({ name: "profile", arguments: { id: "42" } });
      expect(profile.structuredContent).toEqual({ id: "42", email: "[EMAIL_0001]" });

      const resource = await client.readResource({ uri: "crm://customers/42" });
      expect(resource.contents[0]).toMatchObject({ text: "Owner: [EMAIL_0001]" });

      const prompt = await client.getPrompt({
        name: "follow_up",
        arguments: { email: "[EMAIL_0001]" },
      });
      expect(received.at(-1)).toEqual({ prompt: "follow_up", email: "ada@example.com" });
      expect(prompt.messages[0]?.content).toEqual({ type: "text", text: "Write to [EMAIL_0001]." });

      // Other members of the client are its own.
      expect((await client.listTools()).tools.map((tool) => tool.name)).toContain("send_mail");
      expect(client.anonymaGuard.session.size()).toBe(2);
      await client.close();
    });
  });

  describe("runStdioProxy", () => {
    /** Start the proxy in front of the fixture server and talk JSON-RPC to it. */
    function connect(serverArgs: readonly string[] = []) {
      const input = new PassThrough();
      const output = new PassThrough();
      const logs: string[] = [];
      const proxy = runStdioProxy({
        command: process.execPath,
        args: [fixture, "--stdio", ...serverArgs],
        input,
        output,
        log: (line) => logs.push(line),
      });
      const waiting = new Map<unknown, (message: Record<string, unknown>) => void>();
      createInterface({ input: output }).on("line", (line) => {
        const message = JSON.parse(line) as Record<string, unknown>;
        waiting.get(message["id"])?.(message);
      });
      const send = (message: object) => input.write(`${JSON.stringify(message)}\n`);
      const call = (id: number, method: string, params: object) =>
        new Promise<Record<string, unknown>>((resolve) => {
          waiting.set(id, resolve);
          send({ jsonrpc: "2.0", id, method, params });
        });
      const initialize = async () => {
        await call(0, "initialize", {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        });
        send({ jsonrpc: "2.0", method: "notifications/initialized" });
      };
      return { proxy, input, logs, send, call, initialize };
    }

    it("relays a session between a host and a stdio server through the guard", async () => {
      const { proxy, input, logs, call, initialize } = connect(["--noisy"]);
      await initialize();

      const found = await call(1, "tools/call", { name: "find_customer", arguments: { id: "7" } });
      expect(textOf(found["result"])).toBe("Customer 7: [EMAIL_0001], phone [PHONE_0001]");

      const sent = await call(2, "tools/call", {
        name: "send_mail",
        arguments: { to: "[EMAIL_0001]", body: "hi" },
      });
      expect(textOf(sent["result"])).toBe("delivered: true");

      // A result the guard cannot process is answered with an error, never forwarded raw.
      const deep = await call(3, "tools/call", { name: "deep", arguments: {} });
      expect(deep["error"]).toMatchObject({ code: -32603 });
      expect(JSON.stringify(deep)).not.toContain("ada@example.com");

      input.end();
      expect(await proxy.exited).toBe(0);
      expect(logs).toContain("dropped a line from the server that is not JSON");
      expect(
        logs.some((line) => line.includes("could not process a message from the server")),
      ).toBe(true);
      expect(logs.join("\n")).not.toContain("ada@example.com");
    });

    it("ignores blank lines and drops lines from the host that are not JSON", async () => {
      const { proxy, input, logs, initialize } = connect();
      input.write("\n");
      input.write("not json\n");
      await initialize();
      input.end();
      expect(await proxy.exited).toBe(0);
      expect(logs).toEqual(["dropped a line from the host that is not JSON"]);
    });

    it("reports a server that cannot be started", async () => {
      const logs: string[] = [];
      const proxy = runStdioProxy({
        command: "anonyma-test-no-such-command",
        input: new PassThrough(),
        output: new PassThrough(),
        log: (line) => logs.push(line),
      });
      expect(await proxy.exited).toBe(1);
      expect(logs[0]).toMatch(/could not start the server/);
    });

    it("stops the server on close", async () => {
      const { proxy } = connect();
      proxy.close();
      expect(await proxy.exited).toBe(1);
    });
  });
});
