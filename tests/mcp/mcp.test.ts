import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createAuditLogger, memorySink, verifyAuditChain } from "../../src/audit/index.js";
import type { AuditLogger } from "../../src/audit/index.js";
import {
  MCP_PROTOCOL_VERSIONS,
  MCP_RESOURCES,
  MCP_RESOURCE_TEMPLATES,
  MCP_TOOLS,
  createMcpServer,
  serveStdio,
} from "../../src/mcp/index.js";
import type { JsonRpcResponse, McpServer } from "../../src/mcp/index.js";
import { validate } from "../../src/mcp/schema.js";

let nextId = 1;
async function rpc(server: McpServer, method: string, params?: unknown): Promise<JsonRpcResponse> {
  const response = await server.handle({
    jsonrpc: "2.0",
    id: nextId++,
    method,
    ...(params !== undefined ? { params } : {}),
  });
  if (response === undefined) throw new Error("no response");
  return response;
}
async function result<T = Record<string, unknown>>(
  server: McpServer,
  method: string,
  params?: unknown,
): Promise<T> {
  const response = await rpc(server, method, params);
  if (!("result" in response)) throw new Error(`error ${JSON.stringify(response.error)}`);
  return response.result as T;
}
interface ToolResult {
  content: { type: string; text: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}
const call = (server: McpServer, name: string, args: unknown): Promise<ToolResult> =>
  result<ToolResult>(server, "tools/call", { name, arguments: args });

describe("mcp/definitions", () => {
  it("declares tools with object schemas, descriptions and annotations", () => {
    expect(MCP_TOOLS.map((tool) => tool.name)).toEqual([
      "anonyma_detect",
      "anonyma_anonymize",
      "anonyma_tokenize",
      "anonyma_detokenize",
      "anonyma_check_policy",
    ]);
    for (const tool of MCP_TOOLS) {
      expect(tool.name).toMatch(/^[a-zA-Z0-9_-]{1,64}$/);
      expect(tool.description.length).toBeGreaterThan(40);
      expect(tool.inputSchema.type).toBe("object");
      expect(tool.outputSchema.type).toBe("object");
      expect(tool.inputSchema.additionalProperties).toBe(false);
      expect(tool.annotations.openWorldHint).toBe(false);
      expect(() => JSON.stringify(tool)).not.toThrow();
    }
    expect(MCP_RESOURCES.every((resource) => resource.uri.startsWith("anonyma://"))).toBe(true);
    expect(MCP_RESOURCE_TEMPLATES[0]?.uriTemplate).toBe("anonyma://regulations/{id}");
    expect(MCP_PROTOCOL_VERSIONS[0]).toBe("2025-06-18");
  });

  it("validates values against the schema subset", () => {
    const schema = MCP_TOOLS[1]?.inputSchema ?? { type: "object" as const };
    expect(validate(schema, { text: "x", preset: "gdpr", minConfidence: 0.5 })).toEqual([]);
    expect(validate(schema, "x")).toEqual(["/: expected object, got string"]);
    expect(validate(schema, { text: 5 })).toEqual(["/text: expected string, got integer"]);
    expect(validate(schema, { preset: "nope" })).toEqual([
      expect.stringContaining("/preset: must be one of"),
    ]);
    expect(validate(schema, { minConfidence: 2 })).toEqual(["/minConfidence: must be at most 1"]);
    expect(validate(schema, { minConfidence: -1 })).toEqual(["/minConfidence: must be at least 0"]);
    expect(validate(schema, { categories: ["email", "nope"] })).toEqual([
      expect.stringContaining("/categories/1"),
    ]);
    expect(validate(schema, { typo: 1 })).toEqual(["/typo: is not a known parameter"]);
    expect(validate(schema, { strategy: { label: "" } })).toEqual([
      "/strategy/strategy: is required",
      "/strategy/label: must have at least 1 characters",
    ]);
    expect(validate(schema, { strategy: { strategy: "mask", maskChar: "**" } })).toEqual([
      "/strategy/maskChar: must have at most 1 characters",
    ]);
    expect(validate(schema, { text: null })).toEqual(["/text: expected string, got null"]);
    expect(validate({ type: "number" }, 3)).toEqual([]);
    expect(validate({ type: "integer" }, 3.5)).toEqual(["/: expected integer, got number"]);
    expect(validate({ type: "array" }, [1])).toEqual([]);
    expect(
      validate({ type: "object", properties: { a: { type: "boolean" } } }, { a: true, extra: 1 }),
    ).toEqual([]);
  });
});

describe("mcp/server", () => {
  describe("protocol", () => {
    it("negotiates the protocol version and reports its capabilities", async () => {
      const server = createMcpServer();
      const init = await result(server, "initialize", {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "test", version: "0" },
      });
      expect(init).toMatchObject({
        protocolVersion: "2025-03-26",
        capabilities: {
          tools: { listChanged: false },
          resources: { subscribe: false, listChanged: false },
        },
        serverInfo: { name: "anonyma" },
      });
      expect(
        (await result(server, "initialize", { protocolVersion: "1999-01-01" }))["protocolVersion"],
      ).toBe("2025-06-18");
      expect((await result(server, "initialize"))["protocolVersion"]).toBe("2025-06-18");
      expect(await result(server, "ping")).toEqual({});
    });

    it("reports the package version unless told otherwise", async () => {
      const pkg = JSON.parse(
        readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
      ) as { version: string };
      const info = (
        await result<{ serverInfo: { version: string } }>(createMcpServer(), "initialize")
      ).serverInfo;
      expect(info.version).toBe(pkg.version);
      const custom = createMcpServer({ serverInfo: { name: "x", version: "9.9.9" } });
      expect(
        (await result<{ serverInfo: unknown }>(custom, "initialize")).serverInfo,
      ).toMatchObject({ name: "x", version: "9.9.9" });
    });

    it("answers notifications and client responses with nothing", async () => {
      const server = createMcpServer();
      expect(await server.handle({ jsonrpc: "2.0", method: "notifications/initialized" })).toBe(
        undefined,
      );
      expect(await server.handle({ jsonrpc: "2.0", method: "unknown/notification" })).toBe(
        undefined,
      );
      expect(await server.handle({ jsonrpc: "2.0", id: 5, result: {} })).toBe(undefined);
    });

    it("returns JSON-RPC errors for malformed requests, unknown methods and unknown tools", async () => {
      const server = createMcpServer();
      for (const bad of [
        null,
        5,
        "x",
        [],
        { id: 1, method: "ping" },
        { jsonrpc: "2.0", id: 1, method: 5 },
        { jsonrpc: "2.0", id: {}, method: "ping" },
      ]) {
        expect(await server.handle(bad)).toMatchObject({ jsonrpc: "2.0", error: { code: -32600 } });
      }
      expect(await rpc(server, "nope/method")).toMatchObject({ error: { code: -32601 } });
      expect(await rpc(server, "tools/call", { name: "nope", arguments: {} })).toMatchObject({
        error: { code: -32602 },
      });
      expect(await rpc(server, "tools/call")).toMatchObject({ error: { code: -32602 } });
      expect(await rpc(server, "resources/read", { uri: "anonyma://nope" })).toMatchObject({
        error: { code: -32002 },
      });
      expect(
        await rpc(server, "resources/read", { uri: "anonyma://regulations/sox" }),
      ).toMatchObject({ error: { code: -32002 } });
      expect(await rpc(server, "resources/read")).toMatchObject({ error: { code: -32002 } });
      expect(await server.handleLine("{not json")).toBe(
        '{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error."}}',
      );
      expect(
        await server.handleLine('{"jsonrpc":"2.0","method":"notifications/initialized"}'),
      ).toBe(undefined);
      expect(
        JSON.parse((await server.handleLine('{"jsonrpc":"2.0","id":"a","method":"ping"}')) ?? ""),
      ).toEqual({
        jsonrpc: "2.0",
        id: "a",
        result: {},
      });
    });
  });

  describe("tools", () => {
    it("lists the detokenize tool only when the operator enables it", async () => {
      const names = async (server: McpServer): Promise<string[]> =>
        (await result<{ tools: { name: string }[] }>(server, "tools/list")).tools.map(
          (tool) => tool.name,
        );
      expect(await names(createMcpServer())).not.toContain("anonyma_detokenize");
      expect(await names(createMcpServer({ allowDetokenize: true }))).toContain(
        "anonyma_detokenize",
      );
      expect(
        await rpc(createMcpServer(), "tools/call", {
          name: "anonyma_detokenize",
          arguments: { text: "x", session: "12345678" },
        }),
      ).toMatchObject({
        error: { code: -32602 },
      });
    });

    it("detects without returning the detected text", async () => {
      const out = await call(createMcpServer(), "anonyma_detect", {
        text: "Mail alice@example.com from 203.0.113.57",
        categories: ["email", "ipv4"],
      });
      expect(out.structuredContent).toEqual({
        found: true,
        count: 2,
        spans: [
          { start: 5, end: 22, category: "email", confidence: 0.99, detector: "email" },
          { start: 28, end: 40, category: "ipv4", confidence: 0.95, detector: "ipv4" },
        ],
      });
      expect(out.content[0]?.text).toBe(JSON.stringify(out.structuredContent));
      expect(out.content[0]?.text).not.toContain("alice");
      expect(
        (await call(createMcpServer(), "anonyma_detect", { text: "nothing", minConfidence: 0.9 }))
          .structuredContent,
      ).toMatchObject({ found: false, count: 0 });
    });

    it("anonymizes text and JSON, with presets and an explicit strategy", async () => {
      const server = createMcpServer();
      expect(
        (await call(server, "anonyma_anonymize", { text: "Mail alice@example.com" }))
          .structuredContent,
      ).toEqual({
        text: "Mail [REDACTED]",
        replaced: 1,
        fields: [{ path: "", category: "email", detector: "email", rule: "redact", count: 1 }],
      });
      const card = "Card 4111 1111 1111 1111, SSN 123-45-6789";
      expect(
        (await call(server, "anonyma_anonymize", { text: card, preset: "pci-dss" }))
          .structuredContent,
      ).toMatchObject({
        text: "Card ***************1111, SSN 123-45-6789",
        fields: [{ category: "credit-card", rule: "pci-dss" }],
      });
      // An explicit strategy applies to every category of the preset.
      expect(
        (
          await call(server, "anonyma_anonymize", {
            text: card,
            preset: "pci-dss",
            strategy: { strategy: "redact", label: "#" },
          })
        ).structuredContent,
      ).toMatchObject({
        text: "Card #, SSN 123-45-6789",
      });
      const json = await call(server, "anonyma_anonymize", {
        json: { user: { email: "alice@example.com", id: 7 }, notes: ["call 555-867-5309"] },
        strategy: { strategy: "mask", keepTrailing: 2 },
      });
      expect(json.structuredContent).toEqual({
        json: { user: { email: "***************om", id: 7 }, notes: ["call **********09"] },
        replaced: 2,
        fields: [
          { path: "/user/email", category: "email", detector: "email", rule: "mask", count: 1 },
          { path: "/notes/0", category: "phone", detector: "phone", rule: "mask", count: 1 },
        ],
      });
    });

    it("reports tool errors as results, not as protocol errors", async () => {
      const server = createMcpServer();
      for (const args of [
        {},
        { text: "a", json: {} },
        { json: "string" },
        { text: "x", typo: 1 },
        { text: "x", strategy: { strategy: "encrypt" } },
        { text: "x", strategy: { strategy: "mask", maskChar: "" } },
      ]) {
        const out = await call(server, "anonyma_anonymize", args);
        expect(out.isError, JSON.stringify(args)).toBe(true);
        expect(out.structuredContent).toBe(undefined);
      }
      expect(
        (await call(server, "anonyma_tokenize", { text: "x", session: "does-not-exist" }))
          .content[0]?.text,
      ).toBe("Unknown or expired session.");
      expect((await call(server, "anonyma_detect", { text: "x".repeat(1_000_001) })).isError).toBe(
        true,
      );
    });

    it("keeps the token mapping on the server across calls of a session", async () => {
      const server = createMcpServer({ allowDetokenize: true });
      const first = await call(server, "anonyma_tokenize", {
        text: "Mail alice@example.com",
        preset: "pci-dss",
      });
      const session = first.structuredContent?.["session"] as string;
      // Every token carries a tag that is random per session.
      const tag = /^Mail \[EMAIL_([0-9a-f]{8})_0001\]$/.exec(
        first.structuredContent?.["text"] as string,
      )?.[1];
      expect(tag).toBeDefined();
      expect(first.structuredContent).toMatchObject({ replaced: 1 });
      expect(session).toMatch(/^[0-9a-f]{32}$/);
      expect(JSON.stringify(first)).not.toContain("alice");

      const second = await call(server, "anonyma_tokenize", {
        text: "cc bob@example.com and alice@example.com, card 4111 1111 1111 1111",
        session,
        preset: "pci-dss",
      });
      expect(second.structuredContent).toMatchObject({
        text: `cc [EMAIL_${String(tag)}_0002] and [EMAIL_${String(tag)}_0001], card [CREDIT_CARD_${String(tag)}_0001]`,
        session,
      });

      // Text that only looks like a token is not replaced by a stored value.
      const restored = await call(server, "anonyma_detokenize", {
        text: `to [EMAIL_${String(tag)}_0002], not [EMAIL_${String(tag)}_0009], template [EMAIL_0001]`,
        session,
      });
      expect(restored.structuredContent).toEqual({
        text: `to bob@example.com, not [EMAIL_${String(tag)}_0009], template [EMAIL_0001]`,
        restored: 1,
        unresolved: [`[EMAIL_${String(tag)}_0009]`],
      });
    });

    it("answers a batch with one response per request and refuses ids it cannot echo", async () => {
      const server = createMcpServer();
      const batch = await server.handle([
        { jsonrpc: "2.0", id: 1, method: "ping" },
        { jsonrpc: "2.0", method: "notifications/initialized" },
        { jsonrpc: "2.0", id: "b", method: "nope" },
        5,
      ]);
      expect(batch).toEqual([
        { jsonrpc: "2.0", id: 1, result: {} },
        { jsonrpc: "2.0", id: "b", error: { code: -32601, message: "Method not found." } },
        { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid request." } },
      ]);
      expect(await server.handle([{ jsonrpc: "2.0", method: "notifications/initialized" }])).toBe(
        undefined,
      );
      expect(await server.handle([])).toMatchObject({ id: null, error: { code: -32600 } });
      expect(
        JSON.parse(
          (await server.handleLine('[{"jsonrpc":"2.0","id":1,"method":"ping"}]')) ?? "null",
        ),
      ).toEqual([{ jsonrpc: "2.0", id: 1, result: {} }]);
      expect(
        JSON.parse(
          (await server.handleLine('{"jsonrpc":"2.0","id":1e999,"method":"ping"}')) ?? "null",
        ),
      ).toEqual({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid request." } });
    });

    it("rejects an empty or oversized list of categories with a short message", async () => {
      const server = createMcpServer();
      const text = "Mail alice@example.com";
      const empty = await call(server, "anonyma_anonymize", { text, categories: [] });
      expect(empty.isError).toBe(true);
      expect(empty.content[0]?.text).toContain("at least 1 item");
      const huge = await call(server, "anonyma_detect", {
        text,
        categories: Array.from({ length: 50_000 }, () => "x"),
      });
      expect(huge.isError).toBe(true);
      expect(huge.content[0]?.text.length).toBeLessThan(200);
      const wrong = await call(server, "anonyma_detect", {
        text,
        categories: Array.from({ length: 20 }, () => "x"),
      });
      expect(wrong.content[0]?.text).toMatch(/; and 10 more$/);
    });

    it("anonymizes keys and long integers of a JSON value, and limits its size", async () => {
      const server = createMcpServer({ maxJsonLength: 200 });
      const done = await call(server, "anonyma_anonymize", {
        json: { "alice@example.com": { plan: "pro" }, card: 4111111111111111, at: 1700000000 },
      });
      expect(done.structuredContent).toMatchObject({
        json: { "[REDACTED]": { plan: "pro" }, card: "[REDACTED]", at: 1700000000 },
        replaced: 2,
      });
      const large = await call(server, "anonyma_anonymize", {
        json: Array.from({ length: 100 }, () => "row"),
      });
      expect(large.isError).toBe(true);
      expect(large.content[0]?.text).toContain("larger than 200 characters");
    });

    it("drops the least recently used session beyond the limit", async () => {
      const server = createMcpServer({ maxSessions: 2 });
      const open = async (): Promise<string> =>
        (await call(server, "anonyma_tokenize", { text: "a@example.com" })).structuredContent?.[
          "session"
        ] as string;
      const a = await open();
      const b = await open();
      await call(server, "anonyma_tokenize", { text: "x", session: a }); // a is now the most recently used
      await open();
      expect((await call(server, "anonyma_tokenize", { text: "x", session: b })).isError).toBe(
        true,
      );
      expect((await call(server, "anonyma_tokenize", { text: "x", session: a })).isError).toBe(
        undefined,
      );
    });

    it("checks policies and cites the violated provision", async () => {
      const server = createMcpServer();
      const bad = await call(server, "anonyma_check_policy", {
        policy: {
          version: 1,
          id: "p",
          extends: ["hipaa"],
          rules: { ssn: { strategy: "hash" } },
          defaultStrategy: { strategy: "hash" },
        },
      });
      expect(bad.structuredContent?.["valid"]).toBe(false);
      expect(
        (bad.structuredContent?.["issues"] as { citation?: string; path: string }[]).find(
          (issue) => issue.path === "/rules/ssn",
        )?.citation,
      ).toBe("45 CFR § 164.514(b)(2)(i)(G)");
      const good = await call(server, "anonyma_check_policy", {
        policy: { version: 1, id: "p", extends: ["gdpr"] },
      });
      expect(good.structuredContent).toEqual({ valid: true, issues: [] });
    });

    it("records every successful call in the audit log, without content", async () => {
      const sink = memorySink();
      const audit = createAuditLogger({ sinks: [sink] });
      const server = createMcpServer({ audit, allowDetokenize: true });
      await call(server, "anonyma_detect", { text: "alice@example.com" });
      await call(server, "anonyma_anonymize", { text: "alice@example.com" });
      const { structuredContent } = await call(server, "anonyma_tokenize", {
        text: "alice@example.com",
      });
      await call(server, "anonyma_detokenize", {
        text: "[EMAIL_0001]",
        session: structuredContent?.["session"],
      });
      await call(server, "anonyma_check_policy", { policy: { version: 1, id: "p" } });
      await call(server, "anonyma_anonymize", {}); // rejected: not recorded
      expect(
        sink.records().map((record) => [record.operation, record.source, record.fields.length]),
      ).toEqual([
        ["detect", "anonyma_detect", 1],
        ["anonymize", "anonyma_anonymize", 1],
        ["tokenize", "anonyma_tokenize", 1],
        ["detokenize", "anonyma_detokenize", 0],
        ["policy-load", "anonyma_check_policy", 0],
      ]);
      expect(JSON.stringify(sink.records())).not.toContain("alice");
      expect((await verifyAuditChain(sink.records())).ok).toBe(true);
      const head = await result<{ contents: { text: string }[] }>(server, "resources/read", {
        uri: "anonyma://audit/head",
      });
      expect(JSON.parse(head.contents[0]?.text ?? "")).toEqual({ enabled: true, ...audit.head() });
    });
  });

  describe("resources", () => {
    it("lists and reads resources as JSON", async () => {
      const server = createMcpServer();
      expect((await result<{ resources: unknown[] }>(server, "resources/list")).resources).toEqual(
        MCP_RESOURCES,
      );
      expect(
        (await result<{ resourceTemplates: unknown[] }>(server, "resources/templates/list"))
          .resourceTemplates,
      ).toEqual(MCP_RESOURCE_TEMPLATES);
      const read = async (uri: string): Promise<Record<string, unknown>> => {
        const { contents } = await result<{
          contents: { uri: string; mimeType: string; text: string }[];
        }>(server, "resources/read", { uri });
        expect(contents[0]).toMatchObject({ uri, mimeType: "application/json" });
        return JSON.parse(contents[0]?.text ?? "") as Record<string, unknown>;
      };
      expect((await read("anonyma://categories"))["categories"]).toHaveLength(27);
      expect(Object.keys((await read("anonyma://strategies"))["strategies"] as object)).toEqual([
        "redact",
        "mask",
        "pseudonymize",
        "generalize",
        "synthesize",
      ]);
      expect(
        ((await read("anonyma://presets"))["presets"] as { name: string }[]).map(
          (preset) => preset.name,
        ),
      ).toContain("lgpd");
      expect(await read("anonyma://audit/head")).toEqual({ enabled: false });
      const hipaa = await read("anonyma://regulations/hipaa");
      expect(hipaa).toMatchObject({ id: "hipaa", edition: "45 CFR Part 164, Subpart E" });
      expect((hipaa["gaps"] as unknown[]).length).toBeGreaterThan(0);
    });
  });

  describe("serveStdio", () => {
    it("reads newline-delimited messages from arbitrary chunks and writes one line per response", async () => {
      const lines = [
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        "",
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"anonyma_anonymize","arguments":{"text":"é alice@example.com"}}}',
        "garbage",
        '{"jsonrpc":"2.0","id":3,"method":"ping"}',
      ].join("\n");
      const bytes = new TextEncoder().encode(lines);
      async function* input(): AsyncGenerator<string | Uint8Array> {
        // Split inside a multi-byte character and inside a message.
        yield bytes.subarray(0, 150);
        yield bytes.subarray(150, 201);
        yield new TextDecoder().decode(bytes.subarray(201));
      }
      const written: string[] = [];
      await serveStdio(createMcpServer(), {
        input: input(),
        write: (line) => void written.push(line),
      });
      expect(written).toHaveLength(4);
      expect(
        written.every((line) => line.endsWith("\n") && !line.slice(0, -1).includes("\n")),
      ).toBe(true);
      const parsed = written.map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(parsed.map((message) => message["id"])).toEqual([1, 2, null, 3]);
      expect((parsed[1]?.["result"] as ToolResult).structuredContent?.["text"]).toBe(
        "é [REDACTED]",
      );
      expect(parsed[2]).toMatchObject({ error: { code: -32700 } });
    });
  });
});

describe("mcp/server", () => {
  describe("tools", () => {
    it("answers an unexpected failure with a generic internal error that reveals nothing", async () => {
      const failing = createAuditLogger({ sinks: [memorySink()] });
      const audit: AuditLogger = {
        ...failing,
        record: () => Promise.reject(new Error("cannot write the record of alice@example.com")),
      };
      const server = createMcpServer({ audit });
      const response = await rpc(server, "tools/call", {
        name: "anonyma_detect",
        arguments: { text: "mail alice@example.com" },
      });
      expect(response).toMatchObject({ error: { code: -32603, message: "Internal error." } });
      expect(JSON.stringify(response)).not.toContain("alice");
    });
  });
});
