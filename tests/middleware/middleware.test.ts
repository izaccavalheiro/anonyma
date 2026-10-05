import type { AddressInfo } from "node:net";
import { gzipSync } from "node:zlib";
import express from "express";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ValidationError } from "../../src/errors.js";
import { createAuditLogger, memorySink } from "../../src/audit/index.js";
import { compilePipeline } from "../../src/engine/index.js";
import { createScrubber } from "../../src/middleware/index.js";
import { anonymaExpress } from "../../src/middleware/express.js";
import { anonymaHono } from "../../src/middleware/hono.js";

const TICKET = {
  user: { email: "alice@example.com", password: "hunter2" },
  note: "call 555-867-5309",
  n: 7,
};
const SCRUBBED = {
  user: { email: "[REDACTED]", password: "[REDACTED]" },
  note: "call [REDACTED]",
  n: 7,
};
const keyRules = [{ match: "password", category: "credential" }];

describe("middleware/core", () => {
  describe("createScrubber", () => {
    it("scrubs JSON values and text, by spec or by pipeline", () => {
      const scrubber = createScrubber({ keyRules });
      expect(scrubber.json(TICKET, "test")).toEqual(SCRUBBED);
      expect(scrubber.text("mail alice@example.com", "test")).toBe("mail [REDACTED]");
      const pci = createScrubber({ spec: { preset: "pci-dss" } });
      expect(pci.text("card 4111 1111 1111 1111", "t")).toBe("card ***************1111");
      const custom = createScrubber({ pipeline: compilePipeline({ categories: ["email"] }) });
      expect(custom.text("alice@example.com 555-867-5309", "t")).toBe("[REDACTED] 555-867-5309");
      expect(() => createScrubber({ spec: { categories: ["nope" as "email"] } })).toThrow(
        /Unknown PII category/,
      );
    });

    it("dispatches serialised bodies on their content type", () => {
      const scrubber = createScrubber({ keyRules });
      const body = JSON.stringify(TICKET);
      expect(JSON.parse(scrubber.body(body, "application/json; charset=utf-8", "t"))).toEqual(
        SCRUBBED,
      );
      expect(JSON.parse(scrubber.body(body, "application/problem+json", "t"))).toEqual(SCRUBBED);
      expect(scrubber.body("mail alice@example.com", "text/plain", "t")).toBe("mail [REDACTED]");
      expect(scrubber.body('{"broken": "alice@example.com"', "application/json", "t")).toBe(
        '{"broken": "[REDACTED]"',
      );
      expect(scrubber.body("alice@example.com", "application/octet-stream", "t")).toBe(
        "alice@example.com",
      );
      expect(scrubber.body("alice@example.com", undefined, "t")).toBe("alice@example.com");
      expect(scrubber.body("alice@example.com", null, "t")).toBe("alice@example.com");
    });

    it("refuses bodies beyond the size limit instead of passing them on", () => {
      const scrubber = createScrubber({ maxBodyLength: 20 });
      expect(() => scrubber.text("x".repeat(21), "t")).toThrow(ValidationError);
      expect(() =>
        scrubber.body(JSON.stringify({ a: "x".repeat(21) }), "application/json", "t"),
      ).toThrow(ValidationError);
    });

    it("scrubs Fetch API responses and leaves other bodies alone", async () => {
      const scrubber = createScrubber({ keyRules });
      const json = await scrubber.response(
        new Response(JSON.stringify(TICKET), {
          status: 201,
          statusText: "Created",
          headers: {
            "content-type": "application/json",
            "content-length": "999",
            etag: '"abc"',
            "x-request-id": "7",
          },
        }),
        "t",
      );
      expect(json.status).toBe(201);
      expect(await json.json()).toEqual(SCRUBBED);
      expect(json.headers.get("content-length")).toBe(null);
      expect(json.headers.get("etag")).toBe(null);
      expect(json.headers.get("x-request-id")).toBe("7");

      const text = await scrubber.response(
        new Response("mail alice@example.com", { headers: { "content-type": "text/plain" } }),
        "t",
      );
      expect(await text.text()).toBe("mail [REDACTED]");

      const binary = new Response(new Uint8Array([1, 2]), {
        headers: { "content-type": "application/octet-stream" },
      });
      expect(await scrubber.response(binary, "t")).toBe(binary);
      const empty = new Response(null, { status: 204 });
      expect(await scrubber.response(empty, "t")).toBe(empty);
      const untyped = new Response("alice@example.com");
      untyped.headers.delete("content-type");
      expect(await scrubber.response(untyped, "t")).toBe(untyped);
    });

    it("records what was scrubbed, and only when something was", async () => {
      const sink = memorySink();
      const audit = createAuditLogger({ sinks: [sink] });
      const scrubber = createScrubber({ audit, actor: "support-api", policyId: "gdpr", keyRules });
      scrubber.json(TICKET, "POST /tickets");
      scrubber.text("nothing to see", "GET /health");
      scrubber.text("mail alice@example.com", "GET /mail");
      await audit.flush();
      expect(
        sink
          .records()
          .map((r) => [
            r.source,
            r.actor,
            r.policy?.id,
            r.fields.map((f) => `${f.path}:${f.category}`),
          ]),
      ).toEqual([
        [
          "POST /tickets",
          "support-api",
          "gdpr",
          ["/user/email:email", "/user/password:credential", "/note:phone"],
        ],
        ["GET /mail", "support-api", "gdpr", [":email"]],
      ]);
      expect(JSON.stringify(sink.records())).not.toMatch(/alice|hunter2|555-867/);
    });

    it("reports audit failures to the callback without failing the request", async () => {
      const errors: unknown[] = [];
      const audit = createAuditLogger({
        sinks: [
          {
            append: (): void => {
              throw new Error("disk full");
            },
          },
        ],
      });
      const scrubber = createScrubber({ audit, onAuditError: (error) => errors.push(error) });
      expect(scrubber.text("mail alice@example.com", "t")).toBe("mail [REDACTED]");
      await expect(audit.flush()).rejects.toThrow(/sink rejected/);
      expect(errors).toHaveLength(1);
      const silent = createScrubber({ audit });
      expect(silent.text("mail alice@example.com", "t")).toBe("mail [REDACTED]");
      await expect(audit.flush()).rejects.toThrow(/sink rejected/);
    });
  });
});

describe("middleware/express", () => {
  const sink = memorySink();
  const audit = createAuditLogger({ sinks: [sink] });
  const app = express();
  app.use(express.json());
  app.use(express.text());
  app.use("/both", anonymaExpress({ request: true, keyRules, audit }));
  app.post("/both/tickets/:id", (req, res) => {
    res.json({ received: req.body, owner: "bob@example.com" });
  });
  app.post("/both/text", (req, res) => {
    res.type("text/plain").send(`got ${String(req.body)}`);
  });
  app.use("/out", anonymaExpress({ keyRules }));
  app.get("/out/json", (_req, res) => {
    res.json(TICKET);
  });
  app.get("/out/object", (_req, res) => {
    res.send(TICKET);
  });
  app.get("/out/html", (_req, res) => {
    res.send("<p>alice@example.com</p>");
  });
  app.get("/out/typed", (_req, res) => {
    res.type("application/json").send(JSON.stringify(TICKET));
  });
  app.get("/out/buffer", (_req, res) => {
    res.type("application/octet-stream").send(Buffer.from("alice@example.com"));
  });
  app.get("/out/status", (_req, res) => {
    res.status(404).json({ error: "no user alice@example.com" });
  });
  app.get("/out/empty", (_req, res) => {
    res.send();
  });
  app.use("/tiny", anonymaExpress({ maxBodyLength: 10 }));
  app.get("/tiny/text", (_req, res) => {
    res.send("this text about alice@example.com is longer than the limit");
  });
  const cyclic: Record<string, unknown> = {};
  cyclic["self"] = cyclic;
  app.get("/tiny/cyclic", (_req, res) => {
    res.json(cyclic);
  });
  app.use("/in", anonymaExpress({ request: true, response: false }));
  app.post("/in/echo", (req, res) => {
    res.json({ body: req.body, leak: "alice@example.com" });
  });
  app.post("/in/cyclic", anonymaExpress({ request: true, maxBodyLength: 3 }), (req, res) => {
    res.json({ body: req.body });
  });
  app.use((error: unknown, _req: unknown, res: express.Response, _next: unknown) => {
    res.status(422).json({ handled: error instanceof ValidationError });
  });

  let base = "";
  let server: ReturnType<typeof app.listen>;
  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, resolve);
    });
    base = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
  });
  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it("scrubs the parsed request body and the response", async () => {
    const response = await fetch(`${base}/both/tickets/42`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(TICKET),
    });
    expect(await response.json()).toEqual({ received: SCRUBBED, owner: "[REDACTED]" });

    const text = await fetch(`${base}/both/text`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "from alice@example.com",
    });
    expect(await text.text()).toBe("got from [REDACTED]");

    await audit.flush();
    // The audit source is the route pattern, not the URL that was requested.
    // Request bodies are scrubbed before Express has matched a route; the response of the text
    // route had nothing left to scrub, so it produced no record.
    expect(new Set(sink.records().map((record) => record.source))).toEqual(
      new Set(["POST /both/tickets/:id", "POST (unmatched)"]),
    );
    expect(JSON.stringify(sink.records())).not.toMatch(/alice|hunter2|\/42/);
  });

  it("scrubs res.json(), res.send(object), res.send(string) and leaves buffers alone", async () => {
    expect(await (await fetch(`${base}/out/json`)).json()).toEqual(SCRUBBED);
    expect(await (await fetch(`${base}/out/object`)).json()).toEqual(SCRUBBED);
    expect(await (await fetch(`${base}/out/html`)).text()).toBe("<p>[REDACTED]</p>");
    expect(await (await fetch(`${base}/out/typed`)).json()).toEqual(SCRUBBED);
    expect(await (await fetch(`${base}/out/buffer`)).text()).toBe("alice@example.com");
    const notFound = await fetch(`${base}/out/status`);
    expect(notFound.status).toBe(404);
    expect(await notFound.json()).toEqual({ error: "no user [REDACTED]" });
    expect((await fetch(`${base}/out/empty`)).status).toBe(200);
  });

  it("withholds a response it cannot scrub instead of sending the original", async () => {
    for (const path of ["/tiny/text", "/tiny/cyclic"]) {
      const response = await fetch(`${base}${path}`);
      expect(response.status).toBe(500);
      const body = await response.text();
      expect(body).toBe('{"error":"The response could not be sanitized and was withheld."}');
    }
  });

  it("can scrub requests only, and passes scrubbing errors to the error handler", async () => {
    const echo = await fetch(`${base}/in/echo`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com" }),
    });
    expect(await echo.json()).toEqual({ body: { email: "[REDACTED]" }, leak: "alice@example.com" });

    const failing = await fetch(`${base}/in/cyclic`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "too long for the limit",
    });
    expect(failing.status).toBe(422);
    expect(await failing.json()).toEqual({ handled: true });
  });
});

describe("middleware/hono", () => {
  const sink = memorySink();
  const audit = createAuditLogger({ sinks: [sink] });
  const app = new Hono<{ Variables: { anonymaBody: unknown } }>();
  app.use("/both/*", anonymaHono({ request: true, keyRules, audit }));
  app.post("/both/tickets/:id", (c) =>
    c.json({ received: c.get("anonymaBody"), owner: "bob@example.com" }, 201),
  );
  app.use("/out/*", anonymaHono({ keyRules }));
  app.get("/out/json", (c) => c.json(TICKET));
  app.get("/out/text", (c) => c.text("mail alice@example.com"));
  app.get("/out/html", (c) => c.html("<p>alice@example.com</p>"));
  app.get("/out/binary", (c) =>
    c.body(new Uint8Array([1, 2, 3]), 200, { "content-type": "application/octet-stream" }),
  );
  app.use("/tiny/*", anonymaHono({ maxBodyLength: 10 }));
  app.get("/tiny/text", (c) =>
    c.text("this text about alice@example.com is longer than the limit"),
  );
  app.use("/in/*", anonymaHono({ request: true, response: false }));
  app.post("/in/echo", (c) =>
    c.json({ body: c.get("anonymaBody") ?? null, leak: "alice@example.com" }),
  );

  it("scrubs the response and offers a scrubbed copy of the request body", async () => {
    const response = await app.request("/both/tickets/42", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(TICKET),
    });
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({ received: SCRUBBED, owner: "[REDACTED]" });
    await audit.flush();
    expect(sink.records().map((record) => record.source)).toEqual([
      "POST /both/tickets/:id",
      "POST /both/tickets/:id",
    ]);
    expect(JSON.stringify(sink.records())).not.toMatch(/alice|hunter2|\/42/);
  });

  it("scrubs JSON, text and HTML responses and leaves binary responses alone", async () => {
    expect(await (await app.request("/out/json")).json()).toEqual(SCRUBBED);
    expect(await (await app.request("/out/text")).text()).toBe("mail [REDACTED]");
    expect(await (await app.request("/out/html")).text()).toBe("<p>[REDACTED]</p>");
    expect([...new Uint8Array(await (await app.request("/out/binary")).arrayBuffer())]).toEqual([
      1, 2, 3,
    ]);
  });

  it("withholds a response it cannot scrub", async () => {
    const response = await app.request("/tiny/text");
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({
      error: "The response could not be sanitized and was withheld.",
    });
  });

  it("can scrub requests only, and ignores bodies that are not JSON", async () => {
    const post = (body: string, type: string): Promise<Response> =>
      Promise.resolve(
        app.request("/in/echo", { method: "POST", headers: { "content-type": type }, body }),
      );
    expect(
      await (await post(JSON.stringify({ email: "alice@example.com" }), "application/json")).json(),
    ).toEqual({
      body: { email: "[REDACTED]" },
      leak: "alice@example.com",
    });
    expect(await (await post("{broken", "application/json")).json()).toEqual({
      body: null,
      leak: "alice@example.com",
    });
    expect(await (await post("alice@example.com", "text/plain")).json()).toEqual({
      body: null,
      leak: "alice@example.com",
    });
    expect(await (await app.request("/in/echo", { method: "POST" })).json()).toEqual({
      body: null,
      leak: "alice@example.com",
    });
  });

  it("uses a placeholder source when the context has no route pattern", async () => {
    const records = memorySink();
    const log = createAuditLogger({ sinks: [records] });
    const handler = anonymaHono({ audit: log });
    const withPattern = {
      req: {
        method: "GET",
        routePath: "/mw/*",
        matchedRoutes: [{ path: 5 }],
        raw: new Request("https://example.com/x"),
      },
      res: new Response("mail alice@example.com", { headers: { "content-type": "text/plain" } }),
      set: (): void => undefined,
    };
    await handler(withPattern, () => Promise.resolve());
    const context = {
      req: { method: "GET", raw: new Request("https://example.com/users/alice@example.com") },
      res: new Response("mail alice@example.com", { headers: { "content-type": "text/plain" } }),
      set: (): void => undefined,
    };
    await handler(context, () => Promise.resolve());
    await log.flush();
    expect(await context.res.text()).toBe("mail [REDACTED]");
    expect(records.records().map((record) => record.source)).toEqual([
      "GET /mw/*",
      "GET (unmatched)",
    ]);
  });
});

class User {
  public constructor(
    public name: string,
    public email: string,
  ) {}
}

describe("middleware/core", () => {
  describe("createScrubber", () => {
    it("scrubs what JSON.stringify would write for values that are not plain data", () => {
      const scrubber = createScrubber();
      expect(scrubber.json(new User("Alice", "alice@example.com"), "t")).toEqual({
        name: "Alice",
        email: "[REDACTED]",
      });
      expect(scrubber.json({ users: [new User("Bob", "bob@example.com")] }, "t")).toEqual({
        users: [{ name: "Bob", email: "[REDACTED]" }],
      });
      const withToJson = { toJSON: () => ({ email: "carol@example.com" }) };
      expect(JSON.stringify(scrubber.json(withToJson, "t"))).toBe('{"email":"[REDACTED]"}');
      expect(scrubber.json({ at: new Date(0), ok: "dave@example.com" }, "t")).toEqual({
        at: "1970-01-01T00:00:00.000Z",
        ok: "[REDACTED]",
      });
      expect(scrubber.json(undefined, "t")).toBe(undefined);
      expect(scrubber.json(() => "x", "t")).toBeTypeOf("function");
    });

    it("scrubs keys and long numbers, and takes the options that control both", () => {
      const payload = {
        "alice@example.com": { plan: "pro" },
        card: 4111111111111111,
        at: 1700000000,
      };
      expect(createScrubber().json(payload, "t")).toEqual({
        "[REDACTED]": { plan: "pro" },
        card: "[REDACTED]",
        at: 1700000000,
      });
      expect(createScrubber({ keys: "flag", numberDigits: Infinity }).json(payload, "t")).toEqual(
        payload,
      );
      expect(() => createScrubber({ keys: "drop" as "flag" })).toThrow(ValidationError);
    });

    it("returns a JSON body untouched when nothing is replaced, and keeps large integers when something is", () => {
      const scrubber = createScrubber();
      const pretty = '{ "id": 9007199254740993,  "ratio": 1.10, "big": 1e400, "items": [ 1, 2 ] }';
      expect(scrubber.body(pretty, "application/json", "t")).toBe(pretty);
      expect(
        scrubber.body(
          '{"id":9007199254740993,"big":1e400,"email":"alice@example.com"}',
          "application/json",
          "t",
        ),
      ).toBe('{"id":9007199254740993,"big":1e400,"email":"[REDACTED]"}');
    });

    it("treats textual application types as text and scrubs bytes by content type", () => {
      const scrubber = createScrubber();
      expect(
        scrubber.body("<user><email>alice@example.com</email></user>", "application/xml", "t"),
      ).toBe("<user><email>[REDACTED]</email></user>");
      expect(
        scrubber.body('{"a":"alice@example.com"}\n{"b":1}\n', "application/x-ndjson", "t"),
      ).toBe('{"a":"[REDACTED]"}\n{"b":1}\n');
      const bytes = new TextEncoder().encode('{"email":"alice@example.com"}');
      expect(scrubber.bytes(bytes, "application/json", "t")).toBe('{"email":"[REDACTED]"}');
      expect(scrubber.bytes(bytes, "application/octet-stream", "t")).toBe(undefined);
      expect(scrubber.bytes(bytes, null, "t")).toBe(undefined);
      expect(() => scrubber.bytes(new Uint8Array([0xff, 0xfe, 0x41]), "text/plain", "t")).toThrow(
        ValidationError,
      );
      expect(() =>
        createScrubber({ maxBodyLength: 2 }).bytes(new Uint8Array(9), "text/plain", "t"),
      ).toThrow(ValidationError);
    });

    it("decodes a response in its declared character set and answers in UTF-8", async () => {
      const scrubber = createScrubber();
      const latin1 = new Response(Buffer.from("Jos\u00e9 alice@example.com", "latin1"), {
        headers: { "content-type": "text/plain; charset=iso-8859-1" },
      });
      const scrubbed = await scrubber.response(latin1, "t");
      expect(scrubbed.headers.get("content-type")).toBe("text/plain; charset=utf-8");
      expect(await scrubbed.text()).toBe("Jos\u00e9 [REDACTED]");
      await expect(
        scrubber.response(
          new Response("x", { headers: { "content-type": "text/plain; charset=klingon" } }),
          "t",
        ),
      ).rejects.toThrow(ValidationError);
    });

    it("handles a response that is, or only claims to be, compressed", async () => {
      const scrubber = createScrubber();
      const json = '{"email":"alice@example.com"}';
      const headers = { "content-type": "application/json", "content-encoding": "gzip" };
      // Compressed by a handler or by middleware that ran earlier.
      const compressed = await scrubber.response(new Response(gzipSync(json), { headers }), "t");
      expect(compressed.headers.get("content-encoding")).toBe(null);
      expect(await compressed.text()).toBe('{"email":"[REDACTED]"}');
      // A fetch() response: the body is already decoded, the header still says gzip.
      const decoded = await scrubber.response(new Response(json, { headers }), "t");
      expect(decoded.headers.get("content-encoding")).toBe(null);
      expect(await decoded.text()).toBe('{"email":"[REDACTED]"}');
      // Bytes that are neither text nor a format that can be inflated are withheld.
      await expect(
        scrubber.response(
          new Response(new Uint8Array([0x8b, 0xff, 0x00, 0xc3]), {
            headers: { "content-type": "application/json", "content-encoding": "br" },
          }),
          "t",
        ),
      ).rejects.toThrow(ValidationError);
    });

    it("stops reading a response that is longer than the limit", async () => {
      let pulled = 0;
      const endless = new ReadableStream<Uint8Array>({
        pull(controller): void {
          pulled++;
          controller.enqueue(new TextEncoder().encode("x".repeat(64)));
        },
      });
      await expect(
        createScrubber({ maxBodyLength: 100 }).response(
          new Response(endless, { headers: { "content-type": "text/plain" } }),
          "t",
        ),
      ).rejects.toThrow(ValidationError);
      expect(pulled).toBeLessThan(20);
    });

    it("scrubs a stream of server-sent events as it arrives", async () => {
      const sink = memorySink();
      const audit = createAuditLogger({ sinks: [sink] });
      const scrubber = createScrubber({ audit });
      let push: (text: string) => void = () => undefined;
      let close: () => void = () => undefined;
      const upstream = new ReadableStream<Uint8Array>({
        start(controller): void {
          push = (text) => controller.enqueue(new TextEncoder().encode(text));
          close = () => controller.close();
        },
      });
      const response = await scrubber.response(
        new Response(upstream, {
          headers: { "content-type": "text/event-stream", "content-length": "999" },
        }),
        "GET /events",
      );
      expect(response.headers.get("content-type")).toBe("text/event-stream");
      expect(response.headers.get("content-length")).toBe(null);

      const reader = response.body?.pipeThrough(new TextDecoderStream()).getReader();
      if (reader === undefined) throw new Error("unreachable");
      // The first event is delivered while the stream is still open.
      push("data: mail alice@exam");
      push("ple.com\n\ndata: par");
      expect((await reader.read()).value).toBe("data: mail [REDACTED]\n\n");
      push("tial\r\n\r\nid: 7");
      expect((await reader.read()).value).toBe("data: partial\r\n\r\n");
      close();
      expect((await reader.read()).value).toBe("id: 7");
      expect((await reader.read()).done).toBe(true);
      await audit.flush();
      expect(sink.records().map((record) => record.source)).toEqual(["GET /events"]);

      const tiny = await createScrubber({ maxBodyLength: 8 }).response(
        new Response("data: an event that never ends", {
          headers: { "content-type": "text/event-stream" },
        }),
        "t",
      );
      await expect(tiny.text()).rejects.toThrow();
    });
  });
});

describe("middleware/express (payload forms)", () => {
  const app = express();
  app.use(anonymaExpress());
  app.get("/instance", (_req, res) => {
    res.json(new User("Alice", "alice@example.com"));
  });
  app.get("/nested", (_req, res) => {
    res.json({ users: [new User("Bob", "bob@example.com")] });
  });
  app.get("/tojson", (_req, res) => {
    res.json({ toJSON: () => ({ email: "carol@example.com" }) });
  });
  app.get("/keys", (_req, res) => {
    res.json({ "alice@example.com": { plan: "pro" }, card: 4111111111111111 });
  });
  app.get("/bigint", (_req, res) => {
    res.json({ id: 10n, email: "alice@example.com" });
  });
  app.get("/buffer-json", (_req, res) => {
    res.type("json").send(Buffer.from('{"email":"alice@example.com"}'));
  });
  app.get("/buffer-broken", (_req, res) => {
    res.type("text/plain").send(Buffer.from([0xff, 0xfe, 0x41]));
  });
  app.get("/twice", (_req, res) => {
    res.json({ note: "plain" });
  });
  app.use((error: Error, _req: unknown, res: express.Response, _next: unknown) => {
    res.status(500).send(`could not serialise the record of alice@example.com: ${error.message}`);
  });

  let base = "";
  let server: ReturnType<typeof app.listen>;
  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, resolve);
    });
    base = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
  });
  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it("scrubs class instances, objects with toJSON, keys and long numbers", async () => {
    expect(await (await fetch(`${base}/instance`)).json()).toEqual({
      name: "Alice",
      email: "[REDACTED]",
    });
    expect(await (await fetch(`${base}/nested`)).json()).toEqual({
      users: [{ name: "Bob", email: "[REDACTED]" }],
    });
    expect(await (await fetch(`${base}/tojson`)).json()).toEqual({ email: "[REDACTED]" });
    expect(await (await fetch(`${base}/keys`)).json()).toEqual({
      "[REDACTED]": { plan: "pro" },
      card: "[REDACTED]",
    });
  });

  it("still scrubs what an error handler sends after serialising failed", async () => {
    const response = await fetch(`${base}/bigint`);
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).toContain("could not serialise the record of [REDACTED]");
    expect(text).not.toContain("alice");
    // The wrappers stay in place for the next response of the process.
    expect(await (await fetch(`${base}/twice`)).json()).toEqual({ note: "plain" });
  });

  it("scrubs a buffer whose content type says it is JSON or text, and withholds one it cannot read", async () => {
    const json = await fetch(`${base}/buffer-json`);
    expect(await json.json()).toEqual({ email: "[REDACTED]" });
    const broken = await fetch(`${base}/buffer-broken`);
    expect(broken.status).toBe(500);
    expect(await broken.json()).toEqual({
      error: "The response could not be sanitized and was withheld.",
    });
  });
});

describe("middleware/hono (headers and streams)", () => {
  const app = new Hono();
  app.use("*", anonymaHono());
  app.get("/len", (c) => {
    const body = '{"email":"alice@example.com","note":"x"}';
    return c.body(body, 200, {
      "content-type": "application/json",
      "content-length": String(body.length),
      etag: '"of-the-unscrubbed-body"',
    });
  });
  app.get(
    "/pretty",
    () =>
      new Response('{ "ok": true,  "items": [ 1, 2, 3 ], "id": 9007199254740993 }', {
        headers: { "content-type": "application/json", "content-length": "63" },
      }),
  );
  app.get(
    "/proxied",
    () =>
      new Response("mail alice@example.com", {
        headers: {
          "content-type": "text/plain",
          "content-encoding": "gzip",
          "content-length": "57",
        },
      }),
  );
  // The handler writes its second event only when the test lets it.
  let releaseSecondEvent: () => void = () => undefined;
  let secondEventWritten = false;
  app.get("/sse", (c) =>
    streamSSE(c, async (stream) => {
      await stream.writeSSE({ data: "first for alice@example.com" });
      await new Promise<void>((resolve) => {
        releaseSecondEvent = resolve;
      });
      secondEventWritten = true;
      await stream.writeSSE({ data: "second" });
    }),
  );
  const tiny = new Hono();
  tiny.use("*", anonymaHono({ maxBodyLength: 10 }));
  tiny.get("/too-large", (c) =>
    c.body("this text is longer than the limit", 200, {
      "content-type": "text/plain",
      "content-length": "34",
      etag: '"x"',
    }),
  );

  it("does not carry the headers of the unscrubbed body over to the scrubbed one", async () => {
    const response = await app.request("/len");
    const text = await response.text();
    expect(text).toBe('{"email":"[REDACTED]","note":"x"}');
    expect(response.headers.get("etag")).toBe(null);
    expect(response.headers.get("content-length")).toBe(null);

    const proxied = await app.request("/proxied");
    expect(proxied.headers.get("content-encoding")).toBe(null);
    expect(proxied.headers.get("content-length")).toBe(null);
    expect(await proxied.text()).toBe("mail [REDACTED]");

    const withheld = await tiny.request("/too-large");
    expect(withheld.status).toBe(500);
    expect(withheld.headers.get("content-length")).toBe(null);
    expect(withheld.headers.get("etag")).toBe(null);
  });

  it("passes a JSON body without personal data through byte for byte", async () => {
    const response = await app.request("/pretty");
    expect(await response.text()).toBe(
      '{ "ok": true,  "items": [ 1, 2, 3 ], "id": 9007199254740993 }',
    );
  });

  it("delivers server-sent events while the stream is open, scrubbed", async () => {
    const response = await app.request("/sse");
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const reader = response.body?.pipeThrough(new TextDecoderStream()).getReader();
    if (reader === undefined) throw new Error("unreachable");
    // The first event arrives while the handler is still waiting to write the second.
    const first = await reader.read();
    expect(first.value).toBe("data: first for [REDACTED]\n\n");
    expect(secondEventWritten).toBe(false);
    releaseSecondEvent();
    expect((await reader.read()).value).toBe("data: second\n\n");
  });
});
