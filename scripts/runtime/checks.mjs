/**
 * Runtime-neutral feature checks of the built package.
 *
 * This module imports nothing but the files in dist/ and uses nothing but
 * what every target runtime provides (Web Crypto, WHATWG streams, TextEncoder),
 * so it runs unchanged on Node.js, Bun, Deno and Cloudflare Workers (workerd).
 * A check that needs `process`, `Buffer` or a `node:` module fails here
 * instead of in a user's edge deployment.
 *
 * Runners: scripts/runtime/run.mjs (Node.js, Bun, Deno) and
 * scripts/runtime/workerd.mjs (Cloudflare Workers, through Miniflare).
 */

import * as anonyma from "../../dist/index.js";
import * as ai from "../../dist/ai/index.js";
import * as audit from "../../dist/audit/index.js";
import * as engine from "../../dist/engine/index.js";
import * as mcp from "../../dist/mcp/index.js";
import * as middleware from "../../dist/middleware/index.js";
import * as stream from "../../dist/stream.js";
import * as vault from "../../dist/vault/index.js";

const TEXT = "Mail alice@example.com, card 4111 1111 1111 1111, host 192.0.2.1";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function equal(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(
      `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

/** Write every chunk to a transform stream and collect what comes out. */
async function pipeThrough(transform, chunks) {
  const source = new globalThis.ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
  const out = [];
  const reader = source.pipeThrough(transform).getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return out;
    out.push(value);
  }
}

const CHECKS = [
  [
    "detection and the 1.x strategies",
    () => {
      assert(anonyma.detect(TEXT).length >= 3, "expected at least three detections");
      const { text } = anonyma.anonymize(TEXT);
      assert(
        !text.includes("alice@example.com") && !text.includes("192.0.2.1"),
        "PII left in place",
      );
      assert(anonyma.hasPII("alice@example.com") && !anonyma.hasPII("nothing"), "hasPII is wrong");
    },
  ],
  [
    "Web Crypto: SHA-256 hashing, PBKDF2 + AES-256-GCM encryption",
    async () => {
      const digest = await anonyma.hash("value", { pepper: "p" });
      equal(digest, await anonyma.hash("value", { pepper: "p" }), "hashing is not deterministic");
      const sealed = await anonyma.encrypt("value", { passphrase: "secret" });
      equal(await anonyma.decrypt(sealed, { passphrase: "secret" }), "value", "decryption");
      const { text } = await anonyma.anonymizeAsync("Mail alice@example.com", {
        defaultStrategy: { strategy: "hash" },
      });
      assert(/^Mail [0-9a-f]{16}$/.test(text), `hash strategy: ${text}`);
    },
  ],
  [
    "span engine: whole text and chunks",
    () => {
      const pipeline = engine.compilePipeline({ preset: "gdpr" });
      assert(!pipeline.transform(TEXT).text.includes("alice@example.com"), "engine left PII");
      const chunks = engine.createChunkTransformer(engine.compilePipeline(), { batch: 0 });
      equal(
        chunks.push("Mail alice@exam") + chunks.push("ple.com now") + chunks.flush(),
        "Mail [REDACTED] now",
        "chunk-safe streaming",
      );
    },
  ],
  [
    "WHATWG TransformStream wrappers",
    async () => {
      const out = await pipeThrough(stream.createAnonymizeStream(), ["Mail alice@example.com"]);
      assert(!out.join("").includes("alice"), "anonymize stream left PII");
    },
  ],
  [
    "AnonymaVault: {{CATEGORY_N}} tokens and restore()",
    async () => {
      const store = new anonyma.InMemoryVault();
      const { text } = anonyma.tokenize("Mail alice@example.com and bob@example.com", {
        vault: store,
      });
      equal(text, "Mail {{EMAIL_1}} and {{EMAIL_2}}", "vault tokens");
      equal(
        anonyma.restore("{{EMAIL_2}}, {{EMAIL_1}}", store).text,
        "bob@example.com, alice@example.com",
        "restore",
      );
      const remote = new Map();
      const asyncStore = {
        store: async (key, value) => void remote.set(key, value),
        retrieve: async (key) => remote.get(key),
      };
      const result = await anonyma.tokenizeAsync("Mail alice@example.com", { vault: asyncStore });
      equal(
        (await anonyma.restore(result.text, asyncStore)).text,
        "Mail alice@example.com",
        "async vault",
      );
    },
  ],
  [
    "key ring (HKDF, HMAC, PBKDF2 at 100,000 iterations), keyed and sealed tokens",
    async () => {
      const keyring = await vault.createKeyRing({
        namespace: "runtime",
        keys: [{ id: "k1", material: await vault.generateKeyMaterial() }],
      });
      const keyed = vault.createKeyedTokenizer({ keyring, vault: vault.createMemoryVault() });
      const token = await keyed.tokenize("alice@example.com", { category: "email", subject: "s1" });
      equal(await keyed.detokenize(token), "alice@example.com", "keyed tokenizer");
      equal((await keyed.forgetSubject("s1")).erased, 1, "erasure by subject");
      const sealed = vault.createSealedTokenizer({ keyring });
      const sealedToken = await sealed.tokenize("bob@example.com", { category: "email" });
      equal(await sealed.detokenize(sealedToken), "bob@example.com", "sealed tokenizer");
      // A passphrase is stretched with PBKDF2; the lowest count the ring accepts keeps the check fast.
      const stretched = await vault.createKeyRing({
        namespace: "runtime",
        keys: [
          { id: "p1", material: { kind: "passphrase", passphrase: "secret", iterations: 100_000 } },
        ],
      });
      assert(typeof stretched.manifest().mac === "string", "passphrase key ring");
    },
  ],
  [
    "hash-chained audit log",
    async () => {
      const sink = audit.memorySink();
      const logger = audit.createAuditLogger({ sinks: [sink] });
      await logger.record({ operation: "anonymize", fields: [] });
      await logger.record({ operation: "tokenize", fields: [] });
      equal((await audit.verifyAuditChain(sink.records())).ok, true, "audit chain verification");
    },
  ],
  [
    "LLM guard: messages, restoration, streamed restoration",
    async () => {
      const exchange = ai.createLlmGuard({ session: { format: "brace" } }).begin();
      const { messages } = exchange.sanitizeMessages([
        { role: "user", content: "Email alice@example.com" },
      ]);
      equal(messages[0].content, "Email {{EMAIL_1}}", "sanitized message");
      const out = await pipeThrough(exchange.restoreStream(), ["Sent to {", "{EMAIL_", "1}}."]);
      equal(out.join(""), "Sent to alice@example.com.", "streamed restoration");
    },
  ],
  [
    "MCP server and HTTP scrubber",
    async () => {
      const server = mcp.createMcpServer();
      const response = await server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list" });
      assert(Array.isArray(response.result.tools) && response.result.tools.length > 0, "MCP tools");
      const scrubbed = middleware.createScrubber().json({ email: "alice@example.com" }, "runtime");
      assert(!JSON.stringify(scrubbed).includes("alice"), "HTTP scrubber left PII");
    },
  ],
  [
    "receipts, checksums and combined presets",
    async () => {
      const pipeline = engine.compilePipeline({ preset: ["lgpd", "hipaa"] });
      const result = pipeline.transform("CPF 529.982.247-25, CNPJ 11.222.333/0001-81");
      assert(!result.text.includes("529.982") && !result.text.includes("11.222"), "LGPD + HIPAA");
      const receipts = audit.createReceiptIssuer({ key: "runtime-check-key-0123456789abcdef" });
      const receipt = await receipts.issue(result, { input: "x" });
      equal(receipt.total, 2, "receipt total");
      const verified = await receipts.verify(receipt, { output: result.text, input: "x" });
      assert(verified.valid, "receipt did not verify");
      const altered = await receipts.verify({ ...receipt, total: 3 });
      assert(!altered.valid, "altered receipt verified");
    },
  ],
];

/**
 * Run every check.
 *
 * @returns `{ ok, results }`, one result per check.
 */
export async function runChecks() {
  const results = [];
  for (const [name, check] of CHECKS) {
    try {
      await check();
      results.push({ name, ok: true });
    } catch (error) {
      results.push({
        name,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return { ok: results.every((result) => result.ok), results };
}

/** The results as lines of text. */
export function formatResults({ results }) {
  return results.map((result) =>
    result.ok ? `  ok    ${result.name}` : `  FAIL  ${result.name}: ${result.error}`,
  );
}
