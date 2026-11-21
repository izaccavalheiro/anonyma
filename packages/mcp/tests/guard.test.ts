import { describe, expect, it, vi } from "vitest";
import { createMcpGuard } from "../src/index.js";
import type { McpGuardEvent } from "../src/index.js";
import { main, parseArguments } from "../src/cli.js";

/** A JSON-RPC request from the client. */
const request = <P extends object>(id: number | string, method: string, params: P) => ({
  jsonrpc: "2.0",
  id,
  method,
  params,
});

/** A JSON-RPC result from the server. */
const response = (id: number | string, result: object) => ({ jsonrpc: "2.0", id, result });

describe("anonyma-mcp", () => {
  describe("createMcpGuard", () => {
    it("tokenizes tool results and restores tokens in tool arguments", () => {
      const guard = createMcpGuard();
      guard.fromClient(request(1, "tools/call", { name: "find", arguments: { id: "42" } }));
      const result = guard.fromServer(
        response(1, {
          content: [
            { type: "text", text: "Owner ada@example.com, phone 555-867-5309" },
            { type: "image", data: "YWRhQGV4YW1wbGUuY29t", mimeType: "image/png" },
          ],
          structuredContent: { owner: { email: "ada@example.com" } },
          isError: false,
        }),
      );
      expect(result).toEqual(
        response(1, {
          content: [
            { type: "text", text: "Owner [EMAIL_0001], phone [PHONE_0001]" },
            { type: "image", data: "YWRhQGV4YW1wbGUuY29t", mimeType: "image/png" },
          ],
          structuredContent: { owner: { email: "[EMAIL_0001]" } },
          isError: false,
        }),
      );

      const call = request(2, "tools/call", {
        name: "send",
        arguments: { to: "[EMAIL_0001]", cc: ["[email_1]"], note: "call [PHONE_0001]", n: 3 },
      });
      expect(guard.fromClient(call)).toEqual(
        request(2, "tools/call", {
          name: "send",
          arguments: {
            to: "ada@example.com",
            cc: ["ada@example.com"],
            note: "call 555-867-5309",
            n: 3,
          },
        }),
      );
      // The input is not modified.
      expect(call.params.arguments.to).toBe("[EMAIL_0001]");
    });

    it("tokenizes resources, prompts and errors, matched to their requests by id", () => {
      const guard = createMcpGuard({ session: { format: "brace" } });
      guard.fromClient(request("r", "resources/read", { uri: "crm://42" }));
      guard.fromClient(request(7, "prompts/get", { name: "follow_up" }));
      guard.fromClient(request("7", "tools/call", { name: "x" }));

      expect(
        guard.fromServer(
          response("r", {
            contents: [
              { uri: "crm://42", mimeType: "text/plain", text: "ada@example.com" },
              { uri: "crm://42/photo", blob: "AAAA" },
            ],
          }),
        ),
      ).toEqual(
        response("r", {
          contents: [
            { uri: "crm://42", mimeType: "text/plain", text: "{{EMAIL_1}}" },
            { uri: "crm://42/photo", blob: "AAAA" },
          ],
        }),
      );
      expect(
        guard.fromServer(
          response(7, {
            description: "For bob@example.com",
            messages: [
              { role: "user", content: { type: "text", text: "Write to ada@example.com" } },
            ],
          }),
        ),
      ).toEqual(
        response(7, {
          description: "For {{EMAIL_2}}",
          messages: [{ role: "user", content: { type: "text", text: "Write to {{EMAIL_1}}" } }],
        }),
      );
      // The string id "7" is another request than the number 7.
      expect(
        guard.fromServer({
          jsonrpc: "2.0",
          id: "7",
          error: {
            code: -32000,
            message: "No mailbox for ada@example.com",
            data: { who: "bob@example.com" },
          },
        }),
      ).toEqual({
        jsonrpc: "2.0",
        id: "7",
        error: {
          code: -32000,
          message: "No mailbox for {{EMAIL_1}}",
          data: { who: "{{EMAIL_2}}" },
        },
      });
    });

    it("restores prompt arguments and resource URIs", () => {
      const guard = createMcpGuard();
      guard.sanitizeText("ada@example.com");
      expect(
        guard.fromClient(
          request(1, "prompts/get", { name: "p", arguments: { email: "[EMAIL_0001]" } }),
        ),
      ).toEqual(request(1, "prompts/get", { name: "p", arguments: { email: "ada@example.com" } }));
      expect(
        guard.fromClient(request(2, "resources/read", { uri: "mailto:[EMAIL_0001]" })),
      ).toEqual(request(2, "resources/read", { uri: "mailto:ada@example.com" }));
    });

    it("tokenizes sampling requests of the server and restores the client's answer", () => {
      const guard = createMcpGuard();
      const sampling = guard.fromServer(
        request(9, "sampling/createMessage", {
          systemPrompt: "You assist ada@example.com",
          messages: [
            { role: "user", content: { type: "text", text: "Summarise for 555-867-5309" } },
          ],
          maxTokens: 100,
        }),
      );
      expect(sampling).toEqual(
        request(9, "sampling/createMessage", {
          systemPrompt: "You assist [EMAIL_0001]",
          messages: [
            { role: "user", content: { type: "text", text: "Summarise for [PHONE_0001]" } },
          ],
          maxTokens: 100,
        }),
      );
      const answer = response(9, {
        role: "assistant",
        content: { type: "text", text: "Done for [EMAIL_0001]" },
        model: "m",
      });
      expect(guard.fromClient(answer)).toEqual(
        response(9, {
          role: "assistant",
          content: { type: "text", text: "Done for ada@example.com" },
          model: "m",
        }),
      );
      // Answers to other server requests pass unchanged.
      guard.fromServer(request(10, "roots/list", {}));
      const roots = response(10, { roots: [{ uri: "file:///[EMAIL_0001]" }] });
      expect(guard.fromClient(roots)).toBe(roots);
    });

    it("tokenizes log and progress notifications", () => {
      const guard = createMcpGuard();
      expect(
        guard.fromServer({
          jsonrpc: "2.0",
          method: "notifications/message",
          params: { level: "info", data: { user: "ada@example.com" } },
        }),
      ).toEqual({
        jsonrpc: "2.0",
        method: "notifications/message",
        params: { level: "info", data: { user: "[EMAIL_0001]" } },
      });
      expect(
        guard.fromServer({
          jsonrpc: "2.0",
          method: "notifications/progress",
          params: { progressToken: 1, progress: 1, message: "Mailing ada@example.com" },
        }),
      ).toMatchObject({ params: { message: "Mailing [EMAIL_0001]" } });
    });

    it("passes everything else unchanged", () => {
      const guard = createMcpGuard();
      const list = response(1, { tools: [{ name: "x", description: "ada@example.com" }] });
      guard.fromClient(request(1, "tools/list", {}));
      expect(guard.fromServer(list)).toBe(list);
      for (const message of [
        "text",
        null,
        { jsonrpc: "2.0", method: "notifications/initialized" },
        { jsonrpc: "2.0", id: 99, result: { x: "ada@example.com" } },
        { jsonrpc: "2.0", id: null, error: { code: 1, message: "x" } },
        request(3, "ping", {}),
      ]) {
        expect(guard.fromServer(message)).toBe(message);
        expect(guard.fromClient(message)).toBe(message);
      }
    });

    it("handles batches", () => {
      const guard = createMcpGuard();
      guard.fromClient([
        request(1, "tools/call", { name: "a" }),
        request(2, "tools/call", { name: "b" }),
      ]);
      expect(
        guard.fromServer([
          response(1, { content: [{ type: "text", text: "ada@example.com" }] }),
          response(2, { content: [{ type: "text", text: "bob@example.com" }] }),
        ]),
      ).toEqual([
        response(1, { content: [{ type: "text", text: "[EMAIL_0001]" }] }),
        response(2, { content: [{ type: "text", text: "[EMAIL_0002]" }] }),
      ]);
    });

    it("reports what it changed, without content", () => {
      const events: McpGuardEvent[] = [];
      const guard = createMcpGuard({ onEvent: (event) => events.push(event) });
      guard.fromClient(request(1, "tools/call", { name: "a", arguments: { q: "nothing" } }));
      guard.fromServer(
        response(1, { content: [{ type: "text", text: "ada@example.com and bob@example.com" }] }),
      );
      guard.fromClient(request(2, "tools/call", { name: "a", arguments: { to: "[EMAIL_0002]" } }));
      expect(events).toEqual([
        { direction: "to-client", method: "tools/call", replaced: 2 },
        { direction: "to-server", method: "tools/call", replaced: 1 },
      ]);
    });

    it("detects what the spec asks for and continues from a snapshot", () => {
      const first = createMcpGuard({ spec: { categories: ["phone"] } });
      expect(first.sanitizeText("ada@example.com 555-867-5309")).toBe(
        "ada@example.com [PHONE_0001]",
      );
      const second = createMcpGuard({ snapshot: first.session.snapshot() });
      expect(second.restoreText("[PHONE_0001]")).toBe("555-867-5309");
      expect(second.sanitizeText("555-010-0199")).toBe("[PHONE_0002]");
    });

    it("sanitizes results directly, for other transports", () => {
      const guard = createMcpGuard();
      expect(
        guard.sanitizeResult("tools/call", {
          content: [{ type: "text", text: "ada@example.com" }],
        }),
      ).toEqual({ content: [{ type: "text", text: "[EMAIL_0001]" }] });
      expect(guard.sanitizeResult("tools/list", { tools: [] })).toEqual({ tools: [] });
      expect(guard.sanitizeResult("tools/call", "text")).toBe("text");
      expect(guard.restoreValue({ deep: [[["[EMAIL_0001]"]]] })).toEqual({
        deep: [[["ada@example.com"]]],
      });
    });

    it("rejects invalid options", () => {
      expect(() => createMcpGuard({ session: { format: "round" as "brace" } })).toThrow();
      expect(() => createMcpGuard({ spec: { detection: "nope" as "precise" } })).toThrow();
    });
  });

  describe("parseArguments", () => {
    it("parses options and the server command", () => {
      expect(
        parseArguments([
          "--categories",
          "email,phone",
          "--preset",
          "gdpr",
          "--format",
          "brace",
          "--tag",
          "k3Xf",
          "--strict",
          "--quiet",
          "--",
          "npx",
          "-y",
          "server",
        ]),
      ).toEqual({
        quiet: true,
        options: {
          command: "npx",
          args: ["-y", "server"],
          spec: { categories: ["email", "phone"], preset: "gdpr" },
          session: { lenient: false, format: "brace", tag: "k3Xf" },
        },
      });
      expect(parseArguments(["--", "server"])).toEqual({
        quiet: false,
        options: { command: "server", args: [], spec: {}, session: { lenient: true } },
      });
    });

    it("runs from main(): help, usage errors and a server that cannot start", async () => {
      const writes: string[] = [];
      const capture = (chunk: string | Uint8Array) => {
        writes.push(String(chunk));
        return true;
      };
      const out = vi.spyOn(process.stdout, "write").mockImplementation(capture);
      const err = vi.spyOn(process.stderr, "write").mockImplementation(capture);
      try {
        expect(await main(["--help"])).toBe(0);
        expect(await main(["--nope", "--", "x"])).toBe(2);
        expect(await main(["--format", "round", "--", "x"])).toBe(2);
        expect(await main(["--quiet", "--", "anonyma-test-no-such-command"])).toBe(1);
      } finally {
        out.mockRestore();
        err.mockRestore();
      }
      expect(writes.join("")).toContain("Usage: anonyma-mcp-proxy");
      expect(writes.join("")).toContain("could not start the server");
    });

    it("explains usage and rejects what it does not know", () => {
      expect(parseArguments(["--help"])).toMatchObject({ code: 0 });
      expect(parseArguments([])).toMatchObject({ code: 2 });
      expect(parseArguments(["--format"])).toMatchObject({ code: 2 });
      expect(parseArguments(["--format", "--", "x"])).toMatchObject({ code: 2 });
      expect(parseArguments(["--bogus", "--", "x"])).toMatchObject({ code: 2 });
    });
  });
});

describe("package", () => {
  it("has a changelog section for its version and requires anonyma 1.2", async () => {
    const { readFileSync } = await import("node:fs");
    const read = (name: string) => readFileSync(new URL(`../${name}`, import.meta.url), "utf8");
    const pkg = JSON.parse(read("package.json")) as {
      version: string;
      peerDependencies: Record<string, string>;
    };
    expect(read("CHANGELOG.md")).toContain(`## [${pkg.version}]`);
    expect(pkg.peerDependencies["anonyma"]).toBe("^1.2.0");
  });
});
