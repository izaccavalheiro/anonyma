import { webcrypto } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { AuditIntegrityError, ValidationError } from "../../src/errors.js";
import { compilePipeline } from "../../src/engine/index.js";
import {
  GENESIS_HASH,
  canonicalize,
  createAuditLogger,
  hmacSha256Hex,
  inputChecksum,
  jsonPointer,
  lineSink,
  memorySink,
  parseAuditLog,
  sha256Hex,
  summarizeSpans,
  verifyAuditChain,
} from "../../src/audit/index.js";
import type { AuditEvent, AuditRecord } from "../../src/audit/index.js";
import { createKeyRing } from "../../src/vault/index.js";

const event: AuditEvent = {
  operation: "anonymize",
  actor: "support-api",
  source: "POST /tickets",
  policy: { id: "gdpr", version: "2026-10", digest: "a".repeat(64) },
  fields: [{ path: "/message", category: "email", detector: "email", rule: "redact", count: 2 }],
  checksums: { output: "b".repeat(64) },
  attributes: { durationMs: 3, cached: false, region: "eu-west-1" },
};

async function macKey(): Promise<CryptoKey> {
  const ring = await createKeyRing({
    namespace: "audit-test",
    keys: [{ id: "k1", material: { kind: "raw", bytes: new Uint8Array(32).fill(9) } }],
  });
  return ring.deriveKey("k1", "audit-mac");
}

describe("audit/canonical", () => {
  describe("canonicalize", () => {
    it("sorts keys, drops undefined members and uses no whitespace", () => {
      expect(canonicalize({ b: 1, a: [true, null, "x"], c: undefined, d: { z: -0, y: 1.5 } })).toBe(
        '{"a":[true,null,"x"],"b":1,"d":{"y":1.5,"z":0}}',
      );
      expect(canonicalize([undefined, "é", "\n"])).toBe('[null,"é","\\n"]');
      expect(canonicalize(null)).toBe("null");
      expect(canonicalize("s")).toBe('"s"');
      expect(canonicalize(false)).toBe("false");
    });

    it("is independent of key insertion order", () => {
      fc.assert(
        fc.property(fc.dictionary(fc.string(), fc.jsonValue()), (object) => {
          const reversed = Object.fromEntries(Object.entries(object).reverse());
          expect(canonicalize(reversed)).toBe(canonicalize(object));
          expect(JSON.parse(canonicalize(object))).toEqual(JSON.parse(JSON.stringify(object)));
        }),
      );
    });

    it("rejects what JSON cannot represent", () => {
      const cyclic: Record<string, unknown> = {};
      cyclic["self"] = cyclic;
      for (const bad of [
        Number.NaN,
        Infinity,
        1n,
        () => 1,
        Symbol("s"),
        undefined,
        cyclic,
        { a: [Number.NaN] },
      ]) {
        expect(() => canonicalize(bad)).toThrow(ValidationError);
      }
      const shared = { n: 1 };
      expect(canonicalize({ a: shared, b: shared })).toBe('{"a":{"n":1},"b":{"n":1}}');
    });
  });

  describe("canonicalize (values that are not plain data)", () => {
    it("rejects objects that would all serialise to the same text and writes holes as null", () => {
      for (const value of [new Date(0), new Map([[1, 2]]), new Set([1]), new (class Point {})()]) {
        expect(() => canonicalize({ value })).toThrow(ValidationError);
      }
      expect(canonicalize(Object.assign(Object.create(null) as object, { a: 1 }))).toBe('{"a":1}');
      // eslint-disable-next-line no-sparse-arrays
      expect(canonicalize([1, , 3])).toBe("[1,null,3]");
      expect(JSON.parse(canonicalize([1, undefined, 3]))).toEqual([1, null, 3]);
    });
  });

  describe("digests", () => {
    it("computes SHA-256 and HMAC-SHA-256 as lower-case hex", async () => {
      expect(await sha256Hex("abc")).toBe(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      );
      const key = await webcrypto.subtle.importKey(
        "raw",
        new TextEncoder().encode("key"),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
      expect(await hmacSha256Hex("The quick brown fox jumps over the lazy dog", key)).toBe(
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
      );
    });
  });
});

describe("audit/fields", () => {
  it("jsonPointer escapes per RFC 6901", () => {
    expect(jsonPointer([])).toBe("");
    expect(jsonPointer(["user", "emails", 0])).toBe("/user/emails/0");
    expect(jsonPointer(["a/b", "c~d", ""])).toBe("/a~1b/c~0d/");
  });

  it("summarizeSpans groups by category and detector and carries no text", () => {
    const pipeline = compilePipeline({ categories: ["email", "ipv4"] });
    const { spans } = pipeline.transform("a@example.com b@example.com 203.0.113.9");
    expect(summarizeSpans(spans, { path: "/body", rule: "redact" })).toEqual([
      { path: "/body", category: "email", detector: "email", rule: "redact", count: 2 },
      { path: "/body", category: "ipv4", detector: "ipv4", rule: "redact", count: 1 },
    ]);
    expect(
      summarizeSpans(spans, { rule: (category) => `mask:${category}` }).map((e) => [
        e.path,
        e.rule,
      ]),
    ).toEqual([
      ["", "mask:email"],
      ["", "mask:ipv4"],
    ]);
    expect(summarizeSpans([], { rule: "redact" })).toEqual([]);
  });
});

describe("audit/logger", () => {
  describe("createAuditLogger", () => {
    it("seals records into a chain and freezes them", async () => {
      const sink = memorySink();
      let clock = Date.UTC(2026, 9, 4, 12, 0, 0);
      const audit = createAuditLogger({ sinks: [sink], now: () => clock++ });
      expect(audit.head()).toEqual({ seq: -1, hash: GENESIS_HASH });

      const first = await audit.record(event);
      const second = await audit.record({ operation: "detect", fields: [] });
      expect(first).toMatchObject({
        v: 1,
        seq: 0,
        ts: "2026-10-04T12:00:00.000Z",
        guarded: 0,
        prev: GENESIS_HASH,
      });
      expect(second).toMatchObject({ seq: 1, prev: first.hash, ts: "2026-10-04T12:00:00.001Z" });
      expect(first.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(audit.head()).toEqual({ seq: 1, hash: second.hash });
      expect(sink.records()).toEqual([first, second]);
      expect(
        Object.isFrozen(first) && Object.isFrozen(first.fields) && Object.isFrozen(first.fields[0]),
      ).toBe(true);
      expect(await verifyAuditChain(sink.records(), { expectedHead: audit.head() })).toEqual({
        ok: true,
        count: 2,
        head: audit.head(),
      });
    });

    it("seals in call order even when calls are not awaited", async () => {
      const sink = memorySink();
      const slow = {
        append: (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 2)),
      };
      const audit = createAuditLogger({ sinks: [slow, sink] });
      const pending = [0, 1, 2, 3, 4].map((n) =>
        audit.record({ operation: "detect", fields: [], attributes: { n } }),
      );
      await audit.flush();
      const records = await Promise.all(pending);
      expect(records.map((r) => [r.seq, r.attributes?.["n"]])).toEqual([
        [0, 0],
        [1, 1],
        [2, 2],
        [3, 3],
        [4, 4],
      ]);
      expect((await verifyAuditChain(sink.records())).ok).toBe(true);
    });

    it("blanks strings that look like personal data and counts them", async () => {
      const sink = memorySink();
      const audit = createAuditLogger({ sinks: [sink] });
      const record = await audit.record({
        operation: "anonymize",
        actor: "alice@example.com",
        source: "import from 203.0.113.57",
        policy: { id: "gdpr", version: "for 123-45-6789" },
        fields: [
          {
            path: "/users/alice@example.com/phone",
            category: "phone",
            detector: "phone",
            rule: "redact",
            count: 1,
          },
          { path: "/a~1b/ok", category: "4111 1111 1111 1111", detector: "d", rule: "r", count: 0 },
        ],
        attributes: { note: "call bob@example.com", "carol@example.com": "x", n: 1 },
      });
      const dump = JSON.stringify(record);
      for (const leak of ["alice", "bob@", "carol@", "203.0.113.57", "123-45-6789", "4111"]) {
        expect(dump).not.toContain(leak);
      }
      expect(record.guarded).toBe(7);
      expect(record.fields.map((f) => f.path)).toEqual(["/users/*/phone", "/a~1b/ok"]);
      expect(record).toMatchObject({
        actor: "[GUARDED]",
        source: "[GUARDED]",
        policy: { id: "gdpr", version: "[GUARDED]" },
      });
    });

    it("uses a caller-supplied guard", async () => {
      const audit = createAuditLogger({
        sinks: [memorySink()],
        guard: (value) => value.includes("secret"),
      });
      const record = await audit.record({
        operation: "detect",
        actor: "top-secret",
        source: "a@example.com",
        fields: [],
      });
      expect(record).toMatchObject({ actor: "[GUARDED]", source: "a@example.com", guarded: 1 });
    });

    it("authenticates the chain with a key: a rewritten log does not verify", async () => {
      const key = await macKey();
      const sink = memorySink();
      const audit = createAuditLogger({ sinks: [sink], key });
      await audit.record(event);
      await audit.record(event);
      expect(await verifyAuditChain(sink.records(), { key })).toMatchObject({ ok: true, count: 2 });
      // Without the key the hashes cannot be recomputed, so plain SHA-256 verification fails.
      expect(await verifyAuditChain(sink.records())).toEqual({
        ok: false,
        index: 0,
        reason: "bad-hash",
      });
    });

    it("continues an existing chain", async () => {
      const sink = memorySink();
      const first = createAuditLogger({ sinks: [sink] });
      await first.record(event);
      const second = createAuditLogger({ sinks: [sink], resume: first.head() });
      const record = await second.record(event);
      expect(record).toMatchObject({ seq: 1, prev: first.head().hash });
      expect((await verifyAuditChain(sink.records())).ok).toBe(true);
    });

    it("stops accepting records after a sink failure and keeps the head", async () => {
      const sink = memorySink();
      let fail = false;
      const flaky = {
        append: (): void => {
          if (fail) throw new Error("disk full");
        },
      };
      const audit = createAuditLogger({ sinks: [sink, flaky] });
      const ok = await audit.record(event);
      fail = true;
      await expect(audit.record(event)).rejects.toThrow(AuditIntegrityError);
      fail = false;
      await expect(audit.record(event)).rejects.toMatchObject({ code: "AUDIT_INTEGRITY_ERROR" });
      // A caller that only awaits flush() learns of the failure too.
      await expect(audit.flush()).rejects.toThrow(AuditIntegrityError);
      expect(audit.head()).toEqual({ seq: 0, hash: ok.hash });
    });

    it("reports the record a sink rejected, so recovery can complete it instead of forking the chain", async () => {
      const first = memorySink();
      const second = memorySink();
      let fail = false;
      const flaky = {
        append: (record: AuditRecord): void => {
          if (fail) throw new Error("disk full");
          second.append(record);
        },
      };
      const audit = createAuditLogger({ sinks: [first, flaky] });
      expect(audit.failure()).toBe(undefined);
      await audit.record(event);
      fail = true;
      await expect(audit.record(event)).rejects.toThrow(AuditIntegrityError);

      const failure = audit.failure();
      expect(failure).toMatchObject({ sink: 1, record: { seq: 1 } });
      if (failure === undefined) throw new Error("unreachable");
      expect((failure.cause as Error).message).toBe("disk full");
      // The first sink holds the record, the second does not.
      expect(first.records().map((record) => record.seq)).toEqual([0, 1]);
      expect(second.records().map((record) => record.seq)).toEqual([0]);

      // Recovery: complete the sink that misses it, then continue after it.
      second.append(failure.record);
      const resumed = createAuditLogger({
        sinks: [first, second],
        resume: { seq: failure.record.seq, hash: failure.record.hash },
      });
      await resumed.record(event);
      for (const sink of [first, second]) {
        expect(await verifyAuditChain(sink.records())).toMatchObject({ ok: true, count: 3 });
      }
    });

    it("blanks a number that looks like personal data", async () => {
      const sink = memorySink();
      const audit = createAuditLogger({ sinks: [sink] });
      const record = await audit.record({
        operation: "detect",
        fields: [],
        attributes: { card: 4111111111111111, durationMs: 12, ratio: 0.25, ok: true },
      });
      expect(record.attributes).toEqual({
        card: "[GUARDED]",
        durationMs: 12,
        ratio: 0.25,
        ok: true,
      });
      expect(record.guarded).toBe(1);
    });

    it("computes input checksums that can never be used as record hashes", async () => {
      const key = await macKey();
      const sink = memorySink();
      const audit = createAuditLogger({ sinks: [sink], key });
      await audit.record(event);

      // An attacker who chooses the input asks for the checksum of a forged record.
      const forged = {
        operation: "erase",
        fields: [],
        v: 1,
        seq: 1,
        ts: "2026-01-01T00:00:00.000Z",
        guarded: 0,
        prev: audit.head().hash,
      };
      const oracle = await audit.inputChecksum(canonicalize(forged));
      expect(oracle).toMatch(/^[0-9a-f]{64}$/);
      expect(oracle).toBe(await inputChecksum(canonicalize(forged), key));
      expect(
        await verifyAuditChain([...sink.records(), { ...forged, hash: oracle }], { key }),
      ).toEqual({ ok: false, index: 1, reason: "bad-hash" });
      // The chain hash is not a plain HMAC of the record either.
      const [genuine] = sink.records();
      if (genuine === undefined) throw new Error("unreachable");
      const { hash, ...rest } = genuine;
      expect(await hmacSha256Hex(canonicalize(rest), key)).not.toBe(hash);

      const unkeyed = createAuditLogger({ sinks: [memorySink()] });
      await expect(unkeyed.inputChecksum("text")).rejects.toThrow(ValidationError);
      await expect(audit.inputChecksum(5 as unknown as string)).rejects.toThrow(ValidationError);
    });

    it("rejects malformed events without breaking the chain", async () => {
      const sink = memorySink();
      const audit = createAuditLogger({ sinks: [sink] });
      const bad: unknown[] = [
        null,
        { operation: "explode", fields: [] },
        { operation: "detect", fields: "x" },
        { operation: "detect", fields: [null] },
        {
          operation: "detect",
          fields: [{ path: "/a", category: "c", detector: "d", rule: "r", count: -1 }],
        },
        {
          operation: "detect",
          fields: [{ path: "a", category: "c", detector: "d", rule: "r", count: 1 }],
        },
        {
          operation: "detect",
          fields: [{ path: 1, category: "c", detector: "d", rule: "r", count: 1 }],
        },
        {
          operation: "detect",
          fields: [{ path: "/a", category: 1, detector: "d", rule: "r", count: 1 }],
        },
        { operation: "detect", fields: [], actor: 7 },
        { operation: "detect", fields: [], attributes: { a: { nested: true } } },
        { operation: "detect", fields: [], attributes: { a: Number.NaN } },
        { operation: "detect", fields: [], checksums: { input: "short" } },
        { operation: "detect", fields: [], checksums: { output: "Z".repeat(64) } },
        { operation: "detect", fields: [], policy: { id: "p", digest: 5 } },
      ];
      for (const candidate of bad) {
        await expect(audit.record(candidate as AuditEvent)).rejects.toThrow(ValidationError);
      }
      const record = await audit.record({
        operation: "detect",
        fields: [],
        checksums: { input: "c".repeat(64) },
      });
      expect(record.seq).toBe(0);
      expect(record.checksums).toEqual({ input: "c".repeat(64) });
    });

    it("rejects invalid options", () => {
      expect(() => createAuditLogger({ sinks: [] })).toThrow(ValidationError);
      expect(() => createAuditLogger({ sinks: "x" as unknown as [] })).toThrow(ValidationError);
      for (const resume of [
        { seq: 1.5, hash: GENESIS_HASH },
        { seq: -2, hash: GENESIS_HASH },
        { seq: 0, hash: "nope" },
      ]) {
        expect(() => createAuditLogger({ sinks: [memorySink()], resume })).toThrow(ValidationError);
      }
    });
  });

  describe("parseAuditLog", () => {
    it("treats a line that is not canonical JSON as malformed, even when it parses to the same record", async () => {
      const lines: string[] = [];
      const audit = createAuditLogger({ sinks: [lineSink((line) => void lines.push(line))] });
      await audit.record(event);
      await audit.record(event);
      const [first = "", second = ""] = lines;
      expect(await verifyAuditChain(parseAuditLog(first + second))).toMatchObject({ ok: true });
      // Windows line endings are accepted.
      expect(
        await verifyAuditChain(parseAuditLog(first.replace("\n", "\r\n") + second)),
      ).toMatchObject({ ok: true });

      // A duplicate member in front: JSON.parse keeps the last one, a reader of the text sees the first.
      const edited = second.replace("{", '{"actor":"mallory",');
      expect(JSON.parse(edited)).toEqual(JSON.parse(second));
      expect(await verifyAuditChain(parseAuditLog(first + edited))).toEqual({
        ok: false,
        index: 1,
        reason: "malformed",
      });
      expect(
        await verifyAuditChain(parseAuditLog(first + second.replace(",", ", "))),
      ).toMatchObject({
        ok: false,
        reason: "malformed",
      });
    });
  });

  describe("lineSink and parseAuditLog", () => {
    it("writes one canonical JSON line per record and reads them back", async () => {
      let log = "";
      const audit = createAuditLogger({
        sinks: [
          lineSink((line) => {
            log += line;
          }),
        ],
      });
      await audit.record(event);
      await audit.record({ operation: "erase", fields: [], attributes: { erased: 2 } });
      expect(log.split("\n")).toHaveLength(3);
      expect(log.endsWith("\n")).toBe(true);
      const parsed = parseAuditLog(`\n${log}\n  \n`);
      expect(parsed).toHaveLength(2);
      expect(await verifyAuditChain(parsed, { expectedHead: audit.head() })).toMatchObject({
        ok: true,
        count: 2,
      });
      expect(parseAuditLog('{"a":1}\nnot json\n')).toEqual([{ a: 1 }, null]);
    });
  });
});

describe("audit/verify", () => {
  async function chain(length: number): Promise<AuditRecord[]> {
    const sink = memorySink();
    const audit = createAuditLogger({ sinks: [sink], now: () => 0 });
    for (let i = 0; i < length; i++) await audit.record({ ...event, attributes: { i } });
    return [...sink.records()];
  }

  it("accepts an empty chain and an async source", async () => {
    expect(await verifyAuditChain([])).toEqual({
      ok: true,
      count: 0,
      head: { seq: -1, hash: GENESIS_HASH },
    });
    const records = await chain(2);
    async function* source(): AsyncGenerator<AuditRecord> {
      yield* records;
    }
    expect((await verifyAuditChain(source())).ok).toBe(true);
  });

  it("locates removal, reordering, truncation and malformed entries", async () => {
    const records = await chain(4);
    const [r0, r1, r2, r3] = records as [AuditRecord, AuditRecord, AuditRecord, AuditRecord];
    expect(await verifyAuditChain([r0, r2, r3])).toEqual({
      ok: false,
      index: 1,
      reason: "bad-seq",
    });
    expect(await verifyAuditChain([r0, r2, r1, r3])).toEqual({
      ok: false,
      index: 1,
      reason: "bad-seq",
    });
    expect(await verifyAuditChain([r0, { ...r1, prev: "f".repeat(64) }])).toEqual({
      ok: false,
      index: 1,
      reason: "bad-prev",
    });
    expect(await verifyAuditChain([r1, r2])).toEqual({ ok: false, index: 0, reason: "bad-seq" });
    expect(await verifyAuditChain([r1, r2], { after: { seq: 0, hash: r0.hash } })).toMatchObject({
      ok: true,
      count: 2,
    });
    expect(
      await verifyAuditChain([r0, r1, r2], { expectedHead: { seq: 3, hash: r3.hash } }),
    ).toEqual({
      ok: false,
      index: 3,
      reason: "head-mismatch",
    });
    for (const junk of [
      null,
      "x",
      1,
      [],
      { v: 1 },
      { ...r0, hash: 5 },
      { ...r0, v: 2 },
      { ...r0, extra: Number.NaN },
    ]) {
      expect(await verifyAuditChain([junk])).toEqual({ ok: false, index: 0, reason: "malformed" });
    }
  });

  it("detects any change to any record", async () => {
    const records = await chain(3);
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 2 }),
        fc.constantFrom(
          "actor",
          "source",
          "ts",
          "guarded",
          "operation",
          "fields",
          "policy",
          "attributes",
          "checksums",
        ),
        async (index, member) => {
          const tampered = records.map(
            (record) => JSON.parse(JSON.stringify(record)) as Record<string, unknown>,
          );
          const target = tampered[index] as Record<string, unknown>;
          const original = target[member];
          target[member] =
            typeof original === "string"
              ? `${original}x`
              : typeof original === "number"
                ? original + 1
                : { changed: true };
          const result = await verifyAuditChain(tampered);
          expect(result).toEqual({ ok: false, index, reason: "bad-hash" });
        },
      ),
      { numRuns: 40 },
    );
  });
});
