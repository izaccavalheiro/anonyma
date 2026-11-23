import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { SessionStore, createSidecar } from "../src/index.js";
import type { Sidecar } from "../src/index.js";

let server: Server;
let base: string;
let sidecar: Sidecar;

async function start(
  options: Parameters<typeof createSidecar>[0],
): Promise<[Server, string, Sidecar]> {
  const instance = createSidecar(options);
  const listening = createServer(instance.handle);
  await new Promise<void>((resolve) => listening.listen(0, "127.0.0.1", resolve));
  const { port } = listening.address() as AddressInfo;
  return [listening, `http://127.0.0.1:${String(port)}`, instance];
}

function post(
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetch(base + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

beforeAll(async () => {
  [server, base, sidecar] = await start({ maxBodyBytes: 4096 });
});

afterAll(() => {
  server.close();
});

describe("sidecar", () => {
  it("answers health checks", async () => {
    const response = await fetch(`${base}/healthz`);
    expect(await response.json()).toEqual({ status: "ok" });
  });

  it("describes itself", async () => {
    const info = (await (await fetch(`${base}/v1/info`)).json()) as Record<string, unknown>;
    expect(info).toMatchObject({ name: "anonyma-sidecar", offsets: "code-points", mcp: true });
    expect(info["categories"]).toContain("email");
  });

  it("detects with code-point offsets", async () => {
    const text = "\u{1F4E7} ana@example.com";
    const response = await post("/v1/detect", { text, categories: ["email"] });
    const { matches } = (await response.json()) as { matches: { start: number; value: string }[] };
    expect(matches).toEqual([expect.objectContaining({ value: "ana@example.com", start: 2 })]);
  });

  it("converts the offsets of many matches between astral characters", async () => {
    // Each unit is 18 code points (19 UTF-16 units): the emoji, a space, the address, a space.
    // 150 units stay below the 4,096-byte body limit of this server.
    const text = "\u{1F4E7} ana@example.com ".repeat(150);
    const response = await post("/v1/detect", { text, categories: ["email"] });
    const { matches } = (await response.json()) as { matches: { start: number; end: number }[] };
    expect(matches).toHaveLength(150);
    matches.forEach((match, i) => {
      expect(match).toMatchObject({ start: 2 + 18 * i, end: 17 + 18 * i });
    });
  });

  it("anonymizes with presets and rules", async () => {
    const response = await post("/v1/anonymize", {
      text: "Card 4111 1111 1111 1111, mail ana@example.com",
      preset: "pci-dss",
    });
    const body = (await response.json()) as { text: string; counts: Record<string, number> };
    expect(body.text).toContain("1111, mail [REDACTED]");
    expect(body.text).not.toContain("4111");
    expect(body.counts).toMatchObject({ "credit-card": 1, email: 1 });
  });

  it("detects in many texts in one request, as one request per text would", async () => {
    const texts = ["\u{1F4E7} ana@example.com", "nothing here", "", "call +1 202 555 0102"];
    const response = await post("/v1/detect/batch", { texts, categories: ["email", "phone"] });
    const { results } = (await response.json()) as { results: { matches: unknown[] }[] };
    const single = await Promise.all(
      texts.map(async (text) => {
        const one = await post("/v1/detect", { text, categories: ["email", "phone"] });
        return (await one.json()) as { matches: unknown[] };
      }),
    );
    expect(results).toEqual(single);
    expect(results[0]?.matches).toEqual([expect.objectContaining({ start: 2 })]);
  });

  it("anonymizes many texts in one request, as one request per text would", async () => {
    const texts = ["Card 4111 1111 1111 1111", "mail ana@example.com", ""];
    const response = await post("/v1/anonymize/batch", { texts, preset: "pci-dss" });
    const { results } = (await response.json()) as { results: unknown[] };
    const single = await Promise.all(
      texts.map(async (text) => (await post("/v1/anonymize", { text, preset: "pci-dss" })).json()),
    );
    expect(results).toEqual(single);
    expect(
      ((await (await post("/v1/detect/batch", { texts: [] })).json()) as { results: [] }).results,
    ).toEqual([]);
  });

  it("shields prompts into a session and restores answers", async () => {
    const first = (await (
      await post("/v1/shield", { text: "Mail ana@example.com", categories: ["email"] })
    ).json()) as { text: string; session: string };
    expect(first.text).toBe("Mail {{EMAIL_1}}");

    const second = (await (
      await post("/v1/shield", { text: "cc bob@example.com", session: first.session })
    ).json()) as { text: string };
    expect(second.text).toBe("cc {{EMAIL_2}}");

    const restored = (await (
      await post("/v1/restore", {
        text: "{{EMAIL_1}}, {{EMAIL_2}}, {{EMAIL_3}}",
        session: first.session,
      })
    ).json()) as { text: string; restored: number; unresolved: string[] };
    expect(restored).toEqual({
      text: "ana@example.com, bob@example.com, {{EMAIL_3}}",
      restored: 2,
      unresolved: ["{{EMAIL_3}}"],
    });

    const deleted = await fetch(`${base}/v1/sessions/${first.session}`, { method: "DELETE" });
    expect(deleted.status).toBe(204);
    const gone = await post("/v1/restore", { text: "{{EMAIL_1}}", session: first.session });
    expect(gone.status).toBe(404);
  });

  it("serves MCP", async () => {
    const response = await post("/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" });
    const body = (await response.json()) as { result: { tools: { name: string }[] } };
    expect(body.result.tools.map((tool) => tool.name)).toContain("anonyma_anonymize");
    const notification = await post("/mcp", {
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });
    expect(notification.status).toBe(202);
  });

  it.each([
    ["an unknown endpoint", () => post("/v1/nope", {}), 404],
    ["a wrong method", () => fetch(`${base}/v1/detect`), 405],
    ["a body that is not JSON", () => post("/v1/detect", "{"), 400],
    ["a JSON body that is not an object", () => post("/v1/detect", [1]), 400],
    ["a missing text", () => post("/v1/detect", {}), 400],
    ["batch texts that are not a list", () => post("/v1/detect/batch", { texts: "x" }), 400],
    ["batch texts that are not strings", () => post("/v1/anonymize/batch", { texts: [1] }), 400],
    [
      "a batch with an unknown preset",
      () => post("/v1/detect/batch", { texts: ["x"], preset: "nope" }),
      400,
    ],
    ["an unknown preset", () => post("/v1/anonymize", { text: "x", preset: "nope" }), 400],
    [
      "an invalid strategy",
      () => post("/v1/anonymize", { text: "x", defaultStrategy: { strategy: "nope" } }),
      400,
    ],
    ["a body too large", () => post("/v1/detect", { text: "x".repeat(5000) }), 413],
    ["another content type", () => post("/v1/detect", "{}", { "content-type": "text/plain" }), 415],
    ["an unknown session", () => post("/v1/restore", { text: "x", session: "nope" }), 404],
    ["a session that is not a string", () => post("/v1/shield", { text: "x", session: 1 }), 400],
    [
      "deleting an unknown session",
      () => fetch(`${base}/v1/sessions/nope`, { method: "DELETE" }),
      404,
    ],
  ])("rejects %s", async (_name, request, status) => {
    const response = await request();
    expect(response.status).toBe(status);
  });
});

describe("sidecar with a token", () => {
  it("requires the bearer token except for health checks", async () => {
    const [locked, url] = await start({ token: "s3cret" });
    try {
      expect((await fetch(`${url}/healthz`)).status).toBe(200);
      const denied = await fetch(`${url}/v1/info`);
      expect(denied.status).toBe(401);
      expect(denied.headers.get("www-authenticate")).toBe("Bearer");
      expect(
        (await fetch(`${url}/v1/info`, { headers: { authorization: "Bearer nope" } })).status,
      ).toBe(401);
      expect(
        (await fetch(`${url}/v1/info`, { headers: { authorization: "Bearer s3cret" } })).status,
      ).toBe(200);
    } finally {
      locked.close();
    }
  });

  it("refuses an empty token", () => {
    expect(() => createSidecar({ token: "" })).toThrow(RangeError);
  });
});

describe("SessionStore", () => {
  it("expires sessions and drops the least recently used", () => {
    let now = 0;
    const store = new SessionStore({ maxSessions: 2, ttlMs: 100, now: () => now });
    const a = store.create();
    const b = store.create();
    a.vault.store("{{EMAIL_1}}", "ana@example.com");
    expect(store.get(a.id)).toBe(a);
    store.create();
    expect(store.get(b.id)).toBeUndefined();
    expect(store.size).toBe(2);
    now = 1000;
    expect(store.get(a.id)).toBeUndefined();
    expect(a.vault.size).toBe(0);
    store.sweep();
    expect(store.size).toBe(0);
    expect(store.delete("nope")).toBe(false);
  });

  it("validates its limits", () => {
    expect(() => new SessionStore({ maxSessions: 0 })).toThrow(RangeError);
    expect(() => new SessionStore({ ttlMs: 0 })).toThrow(RangeError);
  });
});

it("keeps the sidecar instance reachable for the suite", () => {
  expect(sidecar.sessions).toBeInstanceOf(SessionStore);
});
