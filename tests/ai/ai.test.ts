import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { AsyncStrategyError, ValidationError } from "../../src/errors.js";
import { compilePipeline } from "../../src/engine/index.js";
import {
  contentLens,
  createLlmGuard,
  createRestoreStream,
  createRestoreTransformer,
  deltaLens,
  restoreChunks,
  restoreJsonText,
  sanitizeJson,
  sanitizeJsonAsync,
  textDeltaLens,
  toLanguageModelMiddleware,
} from "../../src/ai/index.js";
import {
  createKeyRing,
  createKeyedTokenizer,
  createMemoryVault,
  createSessionTokenizer,
} from "../../src/vault/index.js";

const pipeline = compilePipeline();

function shapeOf(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(shapeOf);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, member]) => [key, shapeOf(member)]));
  }
  return typeof value;
}

async function* iterate<T>(items: readonly T[]): AsyncGenerator<T> {
  for (const item of items) yield item;
}

async function collect<T>(source: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const item of source) out.push(item);
  return out;
}

describe("ai/json", () => {
  describe("sanitizeJson", () => {
    it("replaces personal data in strings and keeps keys, nesting, order and other types", () => {
      const input = {
        user: { name: "Alice", email: "alice@example.com", age: 41, active: true, manager: null },
        notes: ["call 555-867-5309", "nothing here", 7],
        empty: {},
      };
      const { value, fields, replaced, flaggedKeys, skipped } = sanitizeJson(input, { pipeline });
      expect(value).toEqual({
        user: { name: "Alice", email: "[REDACTED]", age: 41, active: true, manager: null },
        notes: ["call [REDACTED]", "nothing here", 7],
        empty: {},
      });
      expect(Object.keys(value.user)).toEqual(Object.keys(input.user));
      expect(fields).toEqual([
        { path: "/user/email", category: "email", detector: "email", rule: "email", count: 1 },
        { path: "/notes/0", category: "phone", detector: "phone", rule: "phone", count: 1 },
      ]);
      expect({ replaced, flaggedKeys, skipped }).toEqual({
        replaced: 2,
        flaggedKeys: [],
        skipped: [],
      });
      expect(input.user.email).toBe("alice@example.com");
      expect(JSON.stringify(fields)).not.toContain("alice");
    });

    it("accepts bare strings, arrays, primitives and null at the root", () => {
      expect(sanitizeJson("a@example.com", { pipeline }).value).toBe("[REDACTED]");
      expect(sanitizeJson(["a@example.com"], { pipeline }).value).toEqual(["[REDACTED]"]);
      expect(sanitizeJson(42, { pipeline }).value).toBe(42);
      expect(sanitizeJson(null, { pipeline }).value).toBe(null);
      expect(sanitizeJson(undefined, { pipeline }).value).toBe(undefined);
    });

    it("replaces whole values under key rules, whatever they contain", () => {
      const { value, fields } = sanitizeJson(
        {
          Password: "hunter2",
          pin: 1234,
          verified: true,
          tokens: ["abc", "def"],
          nested: { secretKey: "x" },
          other: "hunter2",
        },
        {
          pipeline,
          keyRules: [
            { match: "password", category: "credential" },
            { match: /^(pin|verified|tokens)$/g, category: "credential" },
            { match: /secret/i, category: "credential" },
          ],
          ruleName: (category) => `key:${category}`,
        },
      );
      expect(value).toEqual({
        Password: "[REDACTED]",
        pin: "[REDACTED]",
        verified: "[REDACTED]",
        tokens: ["[REDACTED]", "[REDACTED]"],
        nested: { secretKey: "[REDACTED]" },
        other: "hunter2",
      });
      expect(
        fields.every((field) => field.detector === "key-rule" && field.rule === "key:credential"),
      ).toBe(true);
      expect(fields.map((field) => field.path)).toEqual([
        "/Password",
        "/pin",
        "/verified",
        "/tokens/0",
        "/tokens/1",
        "/nested/secretKey",
      ]);
    });

    it("leaves values under skipped keys alone and sanitizes JSON documents inside strings", () => {
      const { value, fields } = sanitizeJson(
        {
          role: "a@example.com",
          arguments: '{"to":"alice@example.com","cc":["bob@example.com"],"n":1}',
          broken: { arguments: "not json: alice@example.com" },
          scalar: { arguments: "5" },
        },
        { pipeline, skipKeys: ["role"], jsonStringKeys: ["arguments"] },
      );
      expect(value.role).toBe("a@example.com");
      expect(JSON.parse(value.arguments)).toEqual({ to: "[REDACTED]", cc: ["[REDACTED]"], n: 1 });
      expect(value.broken.arguments).toBe("not json: [REDACTED]");
      expect(value.scalar.arguments).toBe("5");
      expect(fields.map((field) => field.path)).toEqual([
        "/arguments/to",
        "/arguments/cc/0",
        "/broken/arguments",
      ]);
    });

    it("only reports keys that contain personal data when asked to leave them", () => {
      const input = { "alice@example.com": { plan: "pro" }, "a/b~c": { "555-867-5309": true } };
      const { value, flaggedKeys, replaced } = sanitizeJson(input, { pipeline, keys: "flag" });
      expect(value).toEqual(input);
      expect(replaced).toBe(0);
      expect(flaggedKeys).toEqual(["/alice@example.com", "/a~1b~0c/555-867-5309"]);
    });

    it("rewrites keys that contain personal data, and keeps the members apart", () => {
      const input = {
        "alice@example.com": { plan: "pro" },
        "bob@example.com": { plan: "free" },
        "[REDACTED]": "already here",
        "a/b~c": { "555-867-5309": true },
        note: "plain",
      };
      const before = JSON.stringify(input);
      const { value, flaggedKeys, fields, replaced } = sanitizeJson(input, { pipeline });
      expect(JSON.stringify(input)).toBe(before);
      expect(Object.keys(value)).toEqual([
        "[REDACTED]#2",
        "[REDACTED]#3",
        "[REDACTED]",
        "a/b~c",
        "note",
      ]);
      expect(Object.values(value)[0]).toEqual({ plan: "pro" });
      expect(Object.values(value)[1]).toEqual({ plan: "free" });
      expect(JSON.stringify(value)).not.toMatch(/alice|bob|555-867/);
      // Pointers and records carry the new keys, never what was detected.
      expect(flaggedKeys).toEqual(["/[REDACTED]#2", "/[REDACTED]#3", "/a~1b~0c/[REDACTED]"]);
      expect(fields.map((field) => field.path)).toEqual(flaggedKeys);
      expect(replaced).toBe(3);

      const session = createSessionTokenizer();
      const tokenized = sanitizeJson(
        { "alice@example.com": { email: "alice@example.com" } },
        {
          pipeline: compilePipeline(
            { defaultStrategy: { strategy: "tokenize" } },
            { tokenization: session },
          ),
        },
      );
      expect(tokenized.value).toEqual({ "[EMAIL_0001]": { email: "[EMAIL_0001]" } });
      expect(tokenized.fields.map((field) => field.path)).toEqual([
        "/[EMAIL_0001]",
        "/[EMAIL_0001]/email",
      ]);
    });

    it("applies a key rule to everything under the key, shared values included", () => {
      const keyRules = [
        { match: /password|secret/i, category: "credential" },
        { match: "ssn", category: "ssn" },
      ];
      const shared = ["hunter2"];
      const { value, fields } = sanitizeJson(
        {
          password: { current: "hunter2", previous: ["hunter1"], attempts: 3, locked: false },
          ssn: [{ number: "078051120" }],
          secret: ["a", ["b"]],
          notes: shared,
          passwords: shared,
        },
        { pipeline, keyRules },
      );
      expect(value).toEqual({
        password: {
          current: "[REDACTED]",
          previous: ["[REDACTED]"],
          attempts: "[REDACTED]",
          locked: "[REDACTED]",
        },
        ssn: [{ number: "[REDACTED]" }],
        secret: ["[REDACTED]", ["[REDACTED]"]],
        notes: ["hunter2"],
        passwords: ["[REDACTED]"],
      });
      expect(fields.every((field) => field.detector === "key-rule")).toBe(true);
    });

    it("scans long numbers as text and leaves short ones alone", () => {
      const input = {
        card: 4111111111111111,
        created: 1700000000,
        createdMs: 1700000000000,
        phone: 5558675309,
        count: 42,
      };
      expect(sanitizeJson(input, { pipeline }).value).toEqual({ ...input, card: "[REDACTED]" });
      expect(sanitizeJson(input, { pipeline, numberDigits: 0 }).value).toEqual({
        ...input,
        card: "[REDACTED]",
        created: "[REDACTED]",
        phone: "[REDACTED]",
      });
      expect(sanitizeJson(input, { pipeline, numberDigits: Infinity }).value).toEqual(input);
      expect(
        sanitizeJson(input, { pipeline, keyRules: [{ match: "phone", category: "phone" }] }).value,
      ).toEqual({ ...input, card: "[REDACTED]", phone: "[REDACTED]" });
      expect(() => sanitizeJson(input, { pipeline, numberDigits: -1 })).toThrow(ValidationError);
      expect(() => sanitizeJson(input, { pipeline, keys: "drop" as "flag" })).toThrow(
        ValidationError,
      );
    });

    it("keeps a nested JSON document as written when nothing in it is replaced, and its large numbers when something is", () => {
      const untouched = '{ "order_id": 9007199254740993, "amount": 1.10, "big": 1e400 }';
      const options = { pipeline, jsonStringKeys: ["arguments"] };
      expect(sanitizeJson({ arguments: untouched }, options)).toMatchObject({
        value: { arguments: untouched },
        replaced: 0,
      });
      const { value } = sanitizeJson(
        {
          arguments:
            '{"order_id":9007199254740993,"big":1e400,"precise":0.1000000000000000055511151231257827,"to":"alice@example.com","card":4111111111111111110}',
        },
        options,
      );
      expect(value.arguments).toBe(
        '{"order_id":9007199254740993,"big":1e400,"precise":0.1000000000000000055511151231257827,"to":"[REDACTED]","card":"[REDACTED]"}',
      );
    });

    it("leaves out functions, keeps holes, and never aliases skipped values", () => {
      const meta = { tags: ["x"] };
      // eslint-disable-next-line no-sparse-arrays
      const input = { list: ["a", , "c"], meta, toJSON: () => ({ email: "carol@example.com" }) };
      const { value, skipped } = sanitizeJson(input, { pipeline, skipKeys: ["meta"] });
      expect(1 in value.list).toBe(false);
      expect(value.list).toHaveLength(3);
      expect(value.meta).toEqual(meta);
      expect(value.meta).not.toBe(meta);
      expect(value.meta.tags).not.toBe(meta.tags);
      expect(skipped).toEqual(["/toJSON"]);
      expect(JSON.stringify(value)).toBe('{"list":["a",null,"c"],"meta":{"tags":["x"]}}');
    });

    it("scans a large document of repeated keys and values once per distinct string", () => {
      let scans = 0;
      const counting = {
        ...pipeline,
        test: (text: string) => (scans++, pipeline.test(text)),
        transform: (text: string) => (scans++, pipeline.transform(text)),
      };
      const rows = Array.from({ length: 5000 }, (_unused, index) => ({
        id: `row-${String(index % 50)}`,
        status: "active",
        region: "eu-west-1",
        plan: "pro",
      }));
      const { replaced } = sanitizeJson(rows, { pipeline: counting });
      expect(replaced).toBe(0);
      // 4 keys and 53 distinct values, not 40,000 strings.
      expect(scans).toBe(57);
    });

    it("copies non-JSON values by reference instead of destroying them", () => {
      const date = new Date(0);
      const map = new Map([["k", "a@example.com"]]);
      class User {
        public email = "a@example.com";
      }
      const user = new User();
      const { value, skipped } = sanitizeJson({ date, map, user, list: [date] }, { pipeline });
      expect(value.date).toBe(date);
      expect(value.map).toBe(map);
      expect(value.user).toBe(user);
      expect(skipped).toEqual(["/date", "/map", "/user", "/list/0"]);
    });

    it("treats __proto__ and constructor as ordinary keys", () => {
      const input = JSON.parse(
        '{"__proto__":{"isAdmin":true,"email":"a@example.com"},"constructor":"b@example.com"}',
      ) as Record<string, unknown>;
      const { value } = sanitizeJson(input, { pipeline });
      expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
      expect((value as { isAdmin?: unknown }).isAdmin).toBe(undefined);
      expect(Object.keys(value)).toEqual(["__proto__", "constructor"]);
      expect(JSON.parse(JSON.stringify(value))).toEqual(
        JSON.parse(
          '{"__proto__":{"isAdmin":true,"email":"[REDACTED]"},"constructor":"[REDACTED]"}',
        ),
      );
      expect(({} as { isAdmin?: unknown }).isAdmin).toBe(undefined);
    });

    it("processes a shared object once and keeps it shared, and rejects cycles", () => {
      let diamond: Record<string, unknown> = { email: "a@example.com" };
      for (let i = 0; i < 40; i++) diamond = { left: diamond, right: diamond };
      const started = performance.now();
      const { value, replaced } = sanitizeJson(diamond, { pipeline });
      expect(performance.now() - started).toBeLessThan(1000);
      expect(replaced).toBe(1);
      expect((value as { left: unknown; right: unknown }).left).toBe(
        (value as { left: unknown; right: unknown }).right,
      );

      const cyclic: Record<string, unknown> = { a: {} };
      (cyclic["a"] as Record<string, unknown>)["back"] = cyclic;
      expect(() => sanitizeJson(cyclic, { pipeline })).toThrow(/circular/);
      const list: unknown[] = [];
      list.push(list);
      expect(() => sanitizeJson(list, { pipeline })).toThrow(ValidationError);
    });

    it("rejects input nested deeper than maxDepth instead of overflowing the stack", () => {
      let deep: unknown = "a@example.com";
      for (let i = 0; i < 2000; i++) deep = [deep];
      expect(() => sanitizeJson(deep, { pipeline })).toThrow(/maxDepth/);
      let ok: unknown = "a@example.com";
      for (let i = 0; i < 5; i++) ok = { next: ok };
      expect(() => sanitizeJson(ok, { pipeline, maxDepth: 5 })).not.toThrow();
      expect(() => sanitizeJson(ok, { pipeline, maxDepth: 4 })).toThrow(ValidationError);
    });

    it("uses one token mapping for the whole value", () => {
      const session = createSessionTokenizer();
      const tokenizing = compilePipeline(
        { defaultStrategy: { strategy: "tokenize" } },
        { tokenization: session },
      );
      const { value } = sanitizeJson(
        {
          from: "alice@example.com",
          to: "bob@example.com",
          body: "bob@example.com wrote to alice@example.com",
        },
        { pipeline: tokenizing },
      );
      // The 1.x consistentTokens option restarted numbering in every string, giving both people EMAIL_1.
      expect(value).toEqual({
        from: "[EMAIL_0001]",
        to: "[EMAIL_0002]",
        body: "[EMAIL_0002] wrote to [EMAIL_0001]",
      });
    });

    it("requires the asynchronous variant for asynchronous replacers", async () => {
      const keyring = await createKeyRing({
        namespace: "t",
        keys: [{ id: "k1", material: { kind: "raw", bytes: new Uint8Array(32).fill(3) } }],
      });
      const tokenization = createKeyedTokenizer({ keyring, vault: createMemoryVault() });
      const asyncPipeline = compilePipeline(
        { defaultStrategy: { strategy: "tokenize" } },
        { tokenization },
      );
      const input = {
        email: "alice@example.com",
        password: "x",
        arguments: '{"cc":"alice@example.com"}',
      };
      const options = {
        pipeline: asyncPipeline,
        keyRules: [{ match: "password", category: "credential" }],
        jsonStringKeys: ["arguments"],
      };
      expect(() => sanitizeJson({ email: "alice@example.com" }, options)).toThrow(
        AsyncStrategyError,
      );
      expect(() => sanitizeJson({ password: "x" }, options)).toThrow(AsyncStrategyError);

      const { value, replaced } = await sanitizeJsonAsync(input, options);
      expect(replaced).toBe(3);
      expect(value.email).toMatch(/^\[EMAIL_k1_/);
      expect(value.password).toMatch(/^\[CREDENTIAL_k1_/);
      expect(JSON.parse(value.arguments)).toEqual({ cc: value.email });
      expect((await sanitizeJsonAsync({ n: 1, s: "plain" }, options)).value).toEqual({
        n: 1,
        s: "plain",
      });
    });

    it("preserves the shape of any JSON value and never mutates it", () => {
      fc.assert(
        fc.property(fc.jsonValue({ maxDepth: 6 }), (input) => {
          const before = JSON.stringify(input);
          const { value } = sanitizeJson(input, {
            pipeline,
            keys: "flag",
            numberDigits: Infinity,
          });
          expect(JSON.stringify(input)).toBe(before);
          expect(shapeOf(value)).toEqual(shapeOf(input));
        }),
        { numRuns: 200 },
      );
    });
  });
});

describe("ai/restore", () => {
  const session = createSessionTokenizer();
  const email = session.tokenize("alice@example.com", { category: "email" });
  const phone = session.tokenize("555-867-5309", { category: "phone" });
  const answer = `I wrote to ${email} and called ${phone}. [not a token] [EMAIL_0009]`;
  const expected =
    "I wrote to alice@example.com and called 555-867-5309. [not a token] [EMAIL_0009]";

  it("restores tokens split at any position, for any chunking", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.integer({ min: 1, max: 12 }), { minLength: 1, maxLength: 20 }),
        async (sizes) => {
          const restorer = createRestoreTransformer(session);
          let out = "";
          let at = 0;
          for (let i = 0; at < answer.length; i++) {
            const size = sizes[i % sizes.length] ?? 1;
            out += await restorer.push(answer.slice(at, at + size));
            at += size;
          }
          out += await restorer.flush();
          expect(out).toBe(expected);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("emits text as soon as it cannot be part of a token", async () => {
    const restorer = createRestoreTransformer(session);
    expect(await restorer.push("Hello wor")).toBe("Hello wor");
    expect(await restorer.push("ld [EMA")).toBe("ld ");
    expect(await restorer.push("IL_0001] done")).toBe("alice@example.com done");
    expect(await restorer.push(`[${"x".repeat(80)}`)).toBe(`[${"x".repeat(80)}`);
    expect(await restorer.flush()).toBe("");
    expect(await restorer.push("tail [EMAIL_00")).toBe("tail ");
    expect(await restorer.flush()).toBe("[EMAIL_00");
    await expect(restorer.push(1 as unknown as string)).rejects.toThrow(ValidationError);
  });

  it("falls back to a fixed hold-back for providers without a partial pattern", async () => {
    const { partialTokenPattern: _unused, ...rest } = session;
    const restorer = createRestoreTransformer(rest);
    const text = `${"x".repeat(100)} ${email} end`;
    let out = "";
    for (const ch of text) out += await restorer.push(ch);
    expect(out.length).toBeLessThan(text.length);
    expect(out + (await restorer.flush())).toBe(`${"x".repeat(100)} alice@example.com end`);
  });

  it("works as a TransformStream", async () => {
    const stream = createRestoreStream(session);
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    const writing = (async () => {
      for (const chunk of ["to [EMAIL", "_0001", "]", " and [PHONE_0001"])
        await writer.write(chunk);
      await writer.close();
    })();
    let out = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      expect(value.length).toBeGreaterThan(0);
      out += value;
    }
    await writing;
    expect(out).toBe("to alice@example.com and [PHONE_0001");
  });

  it("fails when TransformStream is unavailable", () => {
    const original = globalThis.TransformStream;
    // @ts-expect-error -- simulate a runtime without the Streams API
    delete globalThis.TransformStream;
    try {
      expect(() => createRestoreStream(session)).toThrow(ValidationError);
    } finally {
      globalThis.TransformStream = original;
    }
  });

  it("restores structured chunks through lenses and passes other chunks through", async () => {
    const vercel = await collect(
      restoreChunks(
        iterate<Record<string, unknown>>([
          { type: "stream-start" },
          { type: "text-delta", id: "1", delta: "Hi [EMA" },
          { type: "tool-call", input: "[EMAIL_0001]" },
          { type: "text-delta", id: "1", delta: "IL_0001] and [PHO" },
          { type: "finish" },
        ]),
        textDeltaLens,
        session,
      ),
    );
    // Held text is delivered before the next chunk without text, never after it.
    expect(vercel).toEqual([
      { type: "stream-start" },
      { type: "text-delta", id: "1", delta: "Hi " },
      { type: "text-delta", id: "1", delta: "[EMA" },
      { type: "tool-call", input: "[EMAIL_0001]" },
      { type: "text-delta", id: "1", delta: "IL_0001] and " },
      { type: "text-delta", id: "1", delta: "[PHO" },
      { type: "finish" },
    ]);
    // Blocks that interleave are restored independently.
    const interleaved = await collect(
      restoreChunks(
        iterate<Record<string, unknown>>([
          { type: "text-delta", id: "a", delta: "to [EMA" },
          { type: "text-delta", id: "b", delta: "call [PHO" },
          { type: "text-delta", id: "a", delta: "IL_0001]" },
          { type: "text-delta", id: "b", delta: "NE_0001]" },
        ]),
        textDeltaLens,
        session,
      ),
    );
    expect(interleaved.map((chunk) => `${String(chunk["id"])}:${String(chunk["delta"])}`)).toEqual([
      "a:to ",
      "b:call ",
      "a:alice@example.com",
      "b:555-867-5309",
    ]);
    expect(textDeltaLens.get({ type: "text-delta", textDelta: "x" })).toBe("x");
    expect(textDeltaLens.set({ type: "text-delta", textDelta: "x" }, "y")).toEqual({
      type: "text-delta",
      textDelta: "y",
    });
    expect(textDeltaLens.get({ type: "text-delta", delta: 5 })).toBe(undefined);

    class MessageChunk {
      public constructor(public content: unknown) {}
    }
    const langchain = await collect(
      restoreChunks(
        iterate([
          new MessageChunk("to [EMAIL_0001]"),
          new MessageChunk([{ type: "image" }]),
          new MessageChunk("!"),
        ]) as AsyncIterable<Record<string, unknown>>,
        contentLens,
        session,
      ),
    );
    expect(langchain.map((chunk) => chunk["content"])).toEqual([
      "to alice@example.com",
      [{ type: "image" }],
      "!",
    ]);
    expect(langchain[0]).toBeInstanceOf(MessageChunk);

    const llama = await collect(
      restoreChunks(iterate([{ delta: "[PHONE_0001]", raw: 1 }, { raw: 2 }]), deltaLens, session),
    );
    expect(llama).toEqual([{ delta: "555-867-5309", raw: 1 }, { raw: 2 }]);
    expect(
      await collect(restoreChunks(iterate<Record<string, unknown>>([]), deltaLens, session)),
    ).toEqual([]);
  });
});

describe("ai/guard", () => {
  describe("createLlmGuard", () => {
    it("sanitizes chat messages structurally and restores the answer", () => {
      const guard = createLlmGuard({
        skipRoles: ["system"],
        countTokens: (text) => Math.ceil(text.length / 4),
      });
      const exchange = guard.begin();
      const input = [
        { role: "system", content: "Support bot for admin@example.com" },
        { role: "user", content: "Email alice@example.com about invoice 42." },
        {
          role: "user",
          name: "bob@example.com",
          content: [
            { type: "text", text: "Also cc bob@example.com and alice@example.com" },
            { type: "image_url", image_url: { url: "https://example.com/alice@example.com.png" } },
          ],
        },
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_1",
              type: "function",
              function: { name: "send_mail", arguments: '{"to":"alice@example.com"}' },
            },
          ],
        },
        {
          role: "tool",
          tool_call_id: "call_1",
          content: '{"status":"sent","to":"alice@example.com"}',
        },
      ];
      const { messages, fields, replaced, tokens, unscanned } = exchange.sanitizeMessages(input);
      expect(unscanned).toEqual(["/2/content/1/image_url"]);

      expect(messages[0]).toBe(input[0]);
      expect(messages[1]).toEqual({
        role: "user",
        content: "Email [EMAIL_0001] about invoice 42.",
      });
      expect(messages[2]).toEqual({
        role: "user",
        name: "bob@example.com",
        content: [
          { type: "text", text: "Also cc [EMAIL_0002] and [EMAIL_0001]" },
          { type: "image_url", image_url: { url: "https://example.com/alice@example.com.png" } },
        ],
      });
      expect(messages[3]?.tool_calls?.[0]?.function.arguments).toBe('{"to":"[EMAIL_0001]"}');
      expect(messages[4]?.content).toBe('{"status":"sent","to":"[EMAIL_0001]"}');
      expect(shapeOf(messages)).toEqual(shapeOf(input));
      expect(replaced).toBe(5);
      expect(fields.map((field) => field.path)).toEqual([
        "/1/content",
        "/2/content/0/text",
        "/3/tool_calls/0/function/arguments/to",
        "/4/content",
      ]);
      expect(tokens?.before).toBeGreaterThan(tokens?.after ?? Infinity);
      expect(JSON.stringify(messages.slice(1))).not.toMatch(
        /alice@example\.com"|alice@example\.com /,
      );

      expect(exchange.restoreText("Sent to [EMAIL_0001] and [email_2].").text).toBe(
        "Sent to alice@example.com and bob@example.com.",
      );
      expect(exchange.sanitizeText("again alice@example.com")).toBe("again [EMAIL_0001]");
      expect(() => exchange.sanitizeMessages("nope" as unknown as [])).toThrow(ValidationError);
    });

    it("sanitizes tool arguments and tool results at every depth, whatever their keys are called", () => {
      const exchange = createLlmGuard().begin();
      const { messages, unscanned } = exchange.sanitizeMessages([
        {
          role: "assistant",
          content: [
            { type: "text", text: "Looking up alice@example.com" },
            {
              type: "tool_use",
              id: "toolu_1",
              name: "crm_lookup",
              input: {
                id: "alice@example.com",
                name: "Dr. Jane Smith",
                data: { type: "bob@example.com" },
              },
            },
          ],
        },
        {
          role: "user",
          content: [
            {
              type: "tool_result",
              tool_use_id: "toolu_1",
              content: [
                { type: "text", text: "phone 555-867-5309" },
                { type: "image", source: { type: "base64", data: "alice@example.com" } },
              ],
            },
          ],
        },
        {
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolCallId: "call_2",
              toolName: "search",
              output: {
                type: "json",
                value: { rows: [{ id: "bob@example.com", name: "carol@example.com" }] },
              },
            },
          ],
        },
        {
          role: "assistant",
          function_call: { name: "send", arguments: '{"to":"bob@example.com"}' },
          content: null,
        },
        {
          role: "assistant",
          tool_calls: [
            {
              id: "c",
              type: "function",
              function: { name: "f", arguments: { to: "alice@example.com" } },
              note: "bob@example.com",
            },
            "alice@example.com",
          ],
        },
        "alice@example.com",
        {
          role: "user",
          content: { text: "bob@example.com" },
          attachments: [new Date(0)],
          created: 5,
        },
        {
          role: "assistant",
          function_call: "call bob@example.com",
          content: [42, "alice@example.com"],
        },
      ]);
      const sent = JSON.stringify(messages);
      // Only the media part, which is passed on untouched and reported, still carries an address.
      expect(sent.match(/[a-z]+@example\.com/g)).toEqual(["alice@example.com"]);
      expect(unscanned).toEqual(["/1/content/0/content/1/source/data", "/6/attachments/0"]);
      expect(messages[0]).toMatchObject({
        content: [
          { type: "text", text: "Looking up [EMAIL_0001]" },
          {
            type: "tool_use",
            id: "toolu_1",
            name: "crm_lookup",
            input: { id: "[EMAIL_0001]", data: { type: "[EMAIL_0002]" } },
          },
        ],
      });
      expect(messages[2]).toMatchObject({
        content: [
          {
            toolCallId: "call_2",
            toolName: "search",
            output: {
              type: "json",
              value: { rows: [{ id: "[EMAIL_0002]", name: "[EMAIL_0003]" }] },
            },
          },
        ],
      });
      expect(messages[3]).toMatchObject({
        function_call: { name: "send", arguments: '{"to":"[EMAIL_0002]"}' },
      });
      expect(messages[4]).toMatchObject({
        tool_calls: [
          {
            id: "c",
            type: "function",
            function: { name: "f", arguments: { to: "[EMAIL_0001]" } },
            note: "[EMAIL_0002]",
          },
          "[EMAIL_0001]",
        ],
      });
      expect(messages[5]).toBe("[EMAIL_0001]");
      expect(messages[6]).toMatchObject({ content: { text: "[EMAIL_0002]" }, created: 5 });
      expect(messages[7]).toEqual({
        role: "assistant",
        function_call: "call [EMAIL_0002]",
        content: [42, "[EMAIL_0001]"],
      });
    });

    it("restores streamed output and continues a conversation from a snapshot", async () => {
      const guard = createLlmGuard({
        spec: { categories: ["email"] },
        session: { tag: "k3Xf" },
        keyRules: [{ match: "ssn", category: "ssn" }],
      });
      const first = guard.begin();
      const { messages } = first.sanitizeMessages([
        { role: "user", content: "I am alice@example.com", ssn: "078051120" },
      ]);
      expect(messages[0]).toEqual({
        role: "user",
        content: "I am [EMAIL_k3Xf_0001]",
        ssn: "[SSN_k3Xf_0001]",
      });
      expect(first.sanitizeText("call 555-867-5309")).toBe("call 555-867-5309"); // only emails are in scope

      const second = guard.begin(
        JSON.parse(JSON.stringify(first.snapshot())) as ReturnType<typeof first.snapshot>,
      );
      expect(second.sanitizeText("alice@example.com and bob@example.com")).toBe(
        "[EMAIL_k3Xf_0001] and [EMAIL_k3Xf_0002]",
      );
      expect(
        (
          await collect(second.restoreIterable(iterate(["Hello [EMAIL_k3", "Xf_0001], bye", ""])))
        ).join(""),
      ).toBe("Hello alice@example.com, bye");
      expect(await collect(second.restoreIterable(iterate(["tail [EMAIL_k3"])))).toEqual([
        "tail ",
        "[EMAIL_k3",
      ]);

      const stream = second.restoreStream();
      const writer = stream.writable.getWriter();
      void writer.write("[EMAIL_k3Xf_0002]").then(() => writer.close());
      expect((await stream.readable.getReader().read()).value).toBe("bob@example.com");
    });

    it("keeps exchanges apart: a token of one request does not resolve in another", () => {
      const guard = createLlmGuard();
      const a = guard.begin();
      const b = guard.begin();
      a.sanitizeText("alice@example.com");
      expect(b.restoreText("[EMAIL_0001]")).toMatchObject({
        restored: 0,
        unresolved: ["[EMAIL_0001]"],
      });
    });

    it("reports an invalid spec when the guard is created", () => {
      expect(() => createLlmGuard({ spec: { categories: ["nope" as "email"] } })).toThrow(
        /Unknown PII category/,
      );
      expect(() => createLlmGuard({ session: { tag: "!" } })).toThrow(ValidationError);
    });
  });

  describe("toLanguageModelMiddleware", () => {
    const middleware = toLanguageModelMiddleware(createLlmGuard());
    const prompt = [{ role: "user", content: [{ type: "text", text: "Mail alice@example.com" }] }];

    it("sanitizes the prompt and restores a complete response", async () => {
      const params = await middleware.transformParams({ params: { prompt, temperature: 0 } });
      expect(Object.keys(params)).toEqual(["prompt", "temperature"]);
      expect(params).toMatchObject({
        prompt: [{ role: "user", content: [{ type: "text", text: "Mail [EMAIL_0001]" }] }],
        temperature: 0,
      });
      const date = new Date(0);
      const result = await middleware.wrapGenerate({
        params,
        doGenerate: () =>
          Promise.resolve({
            content: [{ type: "text", text: "Sent to [EMAIL_0001]." }],
            usage: { tokens: 3 },
            at: date,
            nothing: null,
          }),
      });
      expect(result).toEqual({
        content: [{ type: "text", text: "Sent to alice@example.com." }],
        usage: { tokens: 3 },
        at: date,
        nothing: null,
      });

      const text = await middleware.transformParams({ params: { prompt: "Mail bob@example.com" } });
      expect(text["prompt"]).toBe("Mail [EMAIL_0001]");
      expect(await middleware.transformParams({ params: { messages: 1 } })).toMatchObject({
        messages: 1,
      });
      // Params that did not pass through transformParams have no mapping: restoring nothing would go unnoticed.
      await expect(
        middleware.wrapGenerate({ params: {}, doGenerate: () => Promise.resolve("[EMAIL_0001]") }),
      ).rejects.toThrow(ValidationError);
      await expect(
        middleware.wrapStream({
          params: { prompt },
          doStream: () => Promise.resolve({ stream: new ReadableStream<unknown>() }),
        }),
      ).rejects.toThrow(ValidationError);
      // A copy of the params still carries the mapping.
      expect(
        await middleware.wrapGenerate({
          params: { ...params },
          doGenerate: () => Promise.resolve("[EMAIL_0001]"),
        }),
      ).toBe("alice@example.com");
      expect(JSON.stringify(params)).not.toContain("alice");
    });

    it("restores the arguments of a tool call as the JSON document they are", async () => {
      const guarded = toLanguageModelMiddleware(
        createLlmGuard({
          keyRules: [
            { match: "address", category: "address" },
            { match: "password", category: "credential" },
          ],
        }),
      );
      const injected = 'x","bcc":"attacker@evil.example","y":"';
      const params = await guarded.transformParams({
        params: {
          prompt: [
            {
              role: "tool",
              content: [
                {
                  type: "tool-result",
                  output: {
                    address: injected,
                    password: 'p"ss\\word',
                    ship: "1 Main St\nSpringfield",
                  },
                },
              ],
            },
          ],
        },
      });
      expect(JSON.stringify(params)).not.toContain("attacker");

      const call = {
        type: "tool-call",
        toolName: "send_mail",
        input: '{"to":"[ADDRESS_0001]","password":"[CREDENTIAL_0001]","subject":"Invoice"}',
      };
      const generated = (await guarded.wrapGenerate({
        params,
        doGenerate: () => Promise.resolve({ content: [call] }),
      })) as { content: { input: string }[] };
      const input = JSON.parse(generated.content[0]?.input ?? "") as Record<string, unknown>;
      // The restored value is one argument, not three.
      expect(input).toEqual({ to: injected, password: 'p"ss\\word', subject: "Invoice" });

      // The same tool call in a stream is restored the same way.
      const { stream } = await guarded.wrapStream({
        params,
        doStream: () =>
          Promise.resolve({
            stream: new ReadableStream<unknown>({
              start(controller): void {
                controller.enqueue(call);
                controller.close();
              },
            }),
          }),
      });
      const { value } = await stream.getReader().read();
      expect(JSON.parse((value as { input: string }).input)).toEqual(input);
    });

    it("hands the account of each sanitized prompt to a callback", async () => {
      const reports: unknown[] = [];
      const reporting = toLanguageModelMiddleware(createLlmGuard(), {
        onSanitized: (report) => reports.push(report),
      });
      await reporting.transformParams({
        params: {
          prompt: [
            {
              role: "user",
              content: [
                { type: "text", text: "Describe this for alice@example.com" },
                { type: "image", image: "https://cdn.example.com/a.png" },
              ],
            },
          ],
        },
      });
      expect(reports).toHaveLength(1);
      expect(reports[0]).toMatchObject({ replaced: 1, unscanned: ["/0/content/1/image"] });
      const blocking = toLanguageModelMiddleware(createLlmGuard(), {
        onSanitized: (report) => {
          if (report.unscanned.length > 0) throw new Error("media is not allowed here");
        },
      });
      expect(() =>
        blocking.transformParams({
          params: { prompt: [{ role: "user", content: [{ type: "image", image: "x" }] }] },
        }),
      ).toThrow("media is not allowed here");
    });

    it("restores text deltas of a streamed response and leaves other parts alone", async () => {
      const params = await middleware.transformParams({ params: { prompt } });
      const parts = [
        { type: "stream-start" },
        { type: "text-delta", id: "0", delta: "Sent to [EMAIL" },
        { type: "text-delta", id: "0", delta: "_0001]" },
        "raw",
        { type: "text-delta", id: "0", delta: " and [EMA" },
        { type: "finish" },
      ];
      const { stream, ...rest } = await middleware.wrapStream({
        params,
        doStream: () =>
          Promise.resolve({
            stream: new ReadableStream<unknown>({
              start(controller): void {
                for (const part of parts) controller.enqueue(part);
                controller.close();
              },
            }),
            request: { id: 1 },
          }),
      });
      expect(rest).toEqual({ request: { id: 1 } });
      const seen: unknown[] = [];
      const reader = stream.getReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        seen.push(value);
      }
      // Nothing arrives after the part that ends the response.
      expect(seen).toEqual([
        { type: "stream-start" },
        { type: "text-delta", id: "0", delta: "Sent to " },
        { type: "text-delta", id: "0", delta: "alice@example.com" },
        "raw",
        { type: "text-delta", id: "0", delta: " and " },
        { type: "text-delta", id: "0", delta: "[EMA" },
        { type: "finish" },
      ]);
    });
  });
});

describe("ai/restore", () => {
  describe("createRestoreTransformer", () => {
    it("accepts in a stream every spelling of a token that whole-text restoration accepts", async () => {
      const exchange = createLlmGuard().begin();
      exchange.sanitizeText("Mail alice@example.com");
      const spellings = [
        "[EMAIL_0001]",
        "[EMAIL_1]",
        "[email_0001]",
        "\\[EMAIL\\_0001\\]",
        "[ EMAIL_0001 ]",
        "<EMAIL_0001>",
        "(EMAIL_0001)",
      ];
      for (const spelling of spellings) {
        const text = `to ${spelling}. Then (see note) and a trailing \\`;
        const whole = exchange.restoreText(text).text;
        expect(whole, spelling).toBe("to alice@example.com. Then (see note) and a trailing \\");
        for (const size of [1, 2, 3, 5, 8, 1000]) {
          const chunks: string[] = [];
          for (let at = 0; at < text.length; at += size) chunks.push(text.slice(at, at + size));
          const streamed = (await collect(exchange.restoreIterable(iterate(chunks)))).join("");
          expect(streamed, `${spelling} in chunks of ${String(size)}`).toBe(whole);
        }
      }
    });

    it("never cuts through a complete token when the provider has no partial pattern", async () => {
      const session = createSessionTokenizer();
      const token = session.tokenize("alice@example.com", { category: "email" });
      const { partialTokenPattern: _unused, ...provider } = session;
      const text = `${"x".repeat(10)}${token}${"y".repeat(60)}`;
      const restorer = createRestoreTransformer(provider);
      expect((await restorer.push(text)) + (await restorer.flush())).toBe(
        `${"x".repeat(10)}alice@example.com${"y".repeat(60)}`,
      );

      await fc.assert(
        fc.asyncProperty(
          fc.array(fc.constantFrom("a", " ", "[", token, "[EMAIL_", "0001]"), { maxLength: 30 }),
          fc.array(fc.integer({ min: 1, max: 20 }), { minLength: 1, maxLength: 20 }),
          async (pieces, sizes) => {
            const input = pieces.join("");
            const streaming = createRestoreTransformer(provider);
            let out = "";
            let at = 0;
            for (let i = 0; at < input.length; i++) {
              const size = sizes[i % sizes.length] ?? 1;
              out += await streaming.push(input.slice(at, at + size));
              at += size;
            }
            out += await streaming.flush();
            expect(out).toBe(session.restore(input).text);
          },
        ),
        { numRuns: 300 },
      );
    });
  });

  describe("restoreJsonText", () => {
    const session = createSessionTokenizer();
    const pipeline = compilePipeline(
      { defaultStrategy: { strategy: "tokenize" } },
      { tokenization: session },
    );
    const { value: sanitized } = sanitizeJson(
      { note: 'she said "hi"\nto bob@example.com', "alice@example.com": 1 },
      { pipeline, keyRules: [{ match: "note", category: "note" }] },
    );

    it("restores values and keys into the parsed document", async () => {
      const document = JSON.stringify(sanitized);
      expect(document).toBe('{"note":"[NOTE_0001]","[EMAIL_0001]":1}');
      const restored = await restoreJsonText(document, session);
      expect(JSON.parse(restored)).toEqual({
        note: 'she said "hi"\nto bob@example.com',
        "alice@example.com": 1,
      });
    });

    it("keeps a document without tokens, and numbers JavaScript cannot hold", async () => {
      const untouched = '{ "id": 9007199254740993 , "n": 1.10 }';
      expect(await restoreJsonText(untouched, session)).toBe(untouched);
      expect(await restoreJsonText('{"id":9007199254740993,"to":"[NOTE_0001]"}', session)).toBe(
        '{"id":9007199254740993,"to":"she said \\"hi\\"\\nto bob@example.com"}',
      );
      expect(await restoreJsonText('"[EMAIL_0001]"', session)).toBe('"alice@example.com"');
      expect(await restoreJsonText('[["[EMAIL_0001]", 1], null]', session)).toBe(
        '[["alice@example.com",1],null]',
      );
    });

    it("restores text that is not JSON as text, and refuses bottomless nesting", async () => {
      expect(await restoreJsonText("mail [EMAIL_0001] {", session)).toBe(
        "mail alice@example.com {",
      );
      await expect(restoreJsonText("[".repeat(600) + "]".repeat(600), session)).rejects.toThrow(
        ValidationError,
      );
      await expect(restoreJsonText(5 as unknown as string, session)).rejects.toThrow(
        ValidationError,
      );
    });
  });
});

describe("ai/guard", () => {
  describe("createLlmGuard", () => {
    const base64 = (length: number, seed: number): string => {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      let state = seed;
      let out = "";
      for (let i = 0; i < length; i++) {
        state = (Math.imul(state, 1103515245) + 12345) >>> 0;
        out += alphabet.charAt(state >>> 26);
      }
      return out;
    };

    it("passes on byte for byte what a provider must get back unchanged", () => {
      for (let seed = 1; seed <= 40; seed++) {
        const input = [
          {
            role: "assistant",
            content: [
              {
                type: "thinking",
                thinking: "Considering alice@example.com",
                signature: base64(512, seed),
              },
              { type: "redacted_thinking", data: base64(800, seed + 100) },
              { type: "reasoning", encrypted_content: base64(1200, seed + 200) },
              {
                type: "text",
                text: "ok",
                providerOptions: { openai: { itemId: `rs_${base64(48, seed + 300)}` } },
              },
            ],
          },
          {
            role: "tool",
            content: [
              {
                type: "tool-result",
                output: {
                  type: "content",
                  value: [
                    { type: "media", data: base64(4000, seed + 400), mediaType: "image/png" },
                    { type: "text", text: "found bob@example.com" },
                  ],
                },
              },
            ],
          },
          { role: "user", content: "x", custom_blob: base64(600, seed + 500) },
        ];
        const guard = createLlmGuard({ passthroughKeys: ["custom_blob"] });
        const { messages, unscanned } = guard.begin().sanitizeMessages(input);
        const [assistant, tool, user] = messages as typeof input;
        const [thinking, redacted, reasoning, text] = assistant?.content ?? [];
        expect(thinking).toEqual({
          type: "thinking",
          thinking: "Considering [EMAIL_0001]",
          signature: (input[0]?.content?.[0] as { signature: string }).signature,
        });
        expect(redacted).toEqual(input[0]?.content?.[1]);
        expect(reasoning).toEqual(input[0]?.content?.[2]);
        expect(text).toEqual(input[0]?.content?.[3]);
        expect(JSON.stringify(tool)).toContain("found [EMAIL_0002]");
        expect(JSON.stringify(tool)).toContain(base64(4000, seed + 400));
        expect(user).toEqual(input[2]);
        expect(unscanned).toEqual([
          "/0/content/0/signature",
          "/0/content/1/data",
          "/0/content/2/encrypted_content",
          "/0/content/3/providerOptions",
          "/1/content/0/output/value/0/data",
          "/2/custom_blob",
        ]);
      }
    });

    it("sanitizes what is written about a media part and passes its payload on", () => {
      const { messages, unscanned, replaced } = createLlmGuard()
        .begin()
        .sanitizeMessages([
          {
            role: "user",
            content: [
              {
                type: "document",
                source: {
                  type: "text",
                  media_type: "text/plain",
                  data: "Patient alice@example.com, SSN 078-05-1120",
                },
                title: "Record of alice@example.com",
                context: "Call 555-867-5309 before sharing",
              },
              {
                type: "document",
                source: {
                  type: "content",
                  content: [{ type: "text", text: "Reach bob@example.com" }],
                },
              },
              {
                type: "file",
                file: {
                  filename: "dave@example.com.pdf",
                  file_data: "data:application/pdf;base64,AAAA",
                },
              },
              {
                type: "image_url",
                image_url: { url: "https://cdn.example.com/carol@example.com.png" },
              },
            ],
          },
        ]);
      const sent = JSON.stringify(messages);
      expect(sent).not.toMatch(/alice@|bob@|dave@|078-05|555-867/);
      // The payloads are untouched, and listed.
      expect(sent).toContain("data:application/pdf;base64,AAAA");
      expect(sent).toContain("https://cdn.example.com/carol@example.com.png");
      expect(unscanned).toEqual(["/0/content/2/file/file_data", "/0/content/3/image_url"]);
      expect(replaced).toBe(6);
    });

    it("refuses a message that is not a plain object instead of passing it on", () => {
      class HumanMessage {
        public additional_kwargs = {};
        public constructor(public content: string) {}
      }
      const exchange = createLlmGuard().begin();
      expect(() =>
        exchange.sanitizeMessages([
          new HumanMessage("my email is alice@example.com"),
          { role: "user", content: "and bob@example.com" },
        ]),
      ).toThrow(/messages\[0\].*sanitizeText/);
      // The supported way: sanitize the text the message is built from.
      const message = new HumanMessage(exchange.sanitizeText("my email is alice@example.com"));
      expect(message.content).toBe("my email is [EMAIL_0001]");
    });

    it("replaces personal data in the keys of tool results and reports the members", () => {
      const exchange = createLlmGuard().begin();
      const { messages, flaggedKeys } = exchange.sanitizeMessages([
        {
          role: "tool",
          content: [{ type: "tool-result", output: { "alice@example.com": { balance: 10 } } }],
        },
      ]);
      expect(JSON.stringify(messages)).toContain('{"[EMAIL_0001]":{"balance":10}}');
      expect(flaggedKeys).toEqual(["/0/content/0/output/[EMAIL_0001]"]);
    });

    it("rejects content that is nested without end", () => {
      let content: unknown = "alice@example.com";
      for (let i = 0; i < 20_000; i++) content = [{ type: "tool_result", content }];
      expect(() =>
        createLlmGuard()
          .begin()
          .sanitizeMessages([{ role: "user", content }]),
      ).toThrow(ValidationError);
    });
  });
});

describe("ai/guard", () => {
  describe("toLanguageModelMiddleware", () => {
    it("cancels the model stream when the restored stream is cancelled", async () => {
      const middleware = toLanguageModelMiddleware(createLlmGuard());
      const params = await middleware.transformParams({
        params: { prompt: "Mail alice@example.com" },
      });
      let cancelled: unknown;
      const { stream } = await middleware.wrapStream({
        params,
        doStream: () =>
          Promise.resolve({
            stream: new ReadableStream<unknown>({
              pull(controller): void {
                controller.enqueue({ type: "text-delta", id: "0", delta: "to [EMAIL_0001] " });
              },
              cancel(reason): void {
                cancelled = reason;
              },
            }),
          }),
      });
      const reader = stream.getReader();
      expect((await reader.read()).value).toEqual({
        type: "text-delta",
        id: "0",
        delta: "to alice@example.com ",
      });
      await reader.cancel("enough");
      expect(cancelled).toBe("enough");
    });
  });
});
