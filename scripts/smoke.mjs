#!/usr/bin/env node
/**
 * Consumer smoke test.
 *
 * Installs a packed tarball into an empty project and checks, with the
 * Node.js that runs this script, that
 *
 * - every subpath of the export map loads through `import` and through
 *   `require`, with the same export names;
 * - no entry point other than "./schemas" needs the optional peer dependency;
 * - the main features work end to end, Web Crypto included.
 *
 * It needs nothing but Node.js and npm, so it also runs on Node.js versions
 * the development tooling no longer supports.
 *
 * Usage: node scripts/smoke.mjs [tarball.tgz]
 *
 * Without an argument the package is packed from the working directory, which
 * must have been built (`npm run build`).
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const [tarballArgument] = process.argv.slice(2);
const project = mkdtempSync(join(tmpdir(), "anonyma-smoke-"));
const windows = process.platform === "win32";
const npm = windows ? "npm.cmd" : "npm";

/** The tarball given on the command line, or one packed from the working directory. */
function tarballPath() {
  if (tarballArgument !== undefined) return resolve(tarballArgument);
  const destination = mkdtempSync(join(tmpdir(), "anonyma-pack-"));
  execFileSync(
    npm,
    ["pack", "--ignore-scripts", "--loglevel=error", "--pack-destination", destination],
    {
      cwd: root,
      stdio: ["ignore", "ignore", "inherit"],
      shell: windows,
    },
  );
  const [packed] = readdirSync(destination).filter((name) => name.endsWith(".tgz"));
  if (packed === undefined) throw new Error("npm pack produced no tarball");
  return join(destination, packed);
}

function run(command, args) {
  execFileSync(command, args, { cwd: project, stdio: "inherit", shell: windows });
}

const ESM_CHECK = `
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const pkg = JSON.parse(
  readFileSync(new URL("./node_modules/anonyma/package.json", import.meta.url), "utf8"),
);
const withPeer = process.argv.includes("--with-peer");
const names = (module) =>
  Object.keys(module)
    .filter((key) => key !== "default" && key !== "module.exports" && key !== "__esModule")
    .sort();

// 1. Every subpath, in both module systems.
const subpaths = Object.keys(pkg.exports).filter((key) => key !== "./package.json");
assert.ok(subpaths.length >= 15, "the export map lost entries");
for (const subpath of subpaths) {
  const specifier = pkg.name + subpath.slice(1);
  if (subpath === "./schemas" && !withPeer) {
    // The only entry point that may need the optional peer dependency.
    await assert.rejects(import(specifier), /zod/, specifier + " must fail for the missing peer only");
    continue;
  }
  const esm = await import(specifier);
  const cjs = require(specifier);
  assert.ok(names(esm).length > 0, specifier + " exports nothing");
  assert.deepEqual(names(esm), names(cjs), "export names differ between import and require: " + specifier);
}
assert.equal(require("anonyma/package.json").version, pkg.version);

// 2. The 1.x API, Web Crypto included (Node.js 18 has no global crypto).
const { anonymize, detect, hash, encrypt, decrypt, ValidationError } = await import("anonyma");
const text = "Mail alice@example.com, card 4111 1111 1111 1111";
assert.ok(detect(text).length >= 2);
assert.ok(!anonymize(text).text.includes("alice@example.com"));
assert.match(await hash("value"), /^[0-9a-f]{16}$/);
assert.equal(await decrypt(await encrypt("value", { passphrase: "p" }), { passphrase: "p" }), "value");

// 3. Engine: whole text and chunks.
const { compilePipeline, createChunkTransformer } = await import("anonyma/engine");
const pipeline = compilePipeline({ preset: "gdpr" });
const scrubbed = pipeline.transform(text);
assert.ok(!scrubbed.text.includes("alice@example.com"));
assert.ok(!scrubbed.text.includes("4111 1111 1111 1111"));
// A value split across two chunks is replaced like in the whole text.
const redacting = compilePipeline();
const chunks = createChunkTransformer(redacting, { batch: 0 });
assert.equal(
  chunks.push("Mail alice@exam") + chunks.push("ple.com now") + chunks.flush(),
  "Mail [REDACTED] now",
);
// One error class across entry points.
assert.throws(() => compilePipeline({ detection: "nope" }), ValidationError);

// 4. Tokenization: session, keyed with a vault, sealed.
const vaultModule = await import("anonyma/vault");
const session = vaultModule.createSessionTokenizer();
const tokenizing = compilePipeline(
  { defaultStrategy: { strategy: "tokenize" } },
  { tokenization: session },
);
assert.equal(tokenizing.transform("Email alice@example.com").text, "Email [EMAIL_0001]");
assert.equal(session.restore("to [EMAIL_0001]").text, "to alice@example.com");

const keyring = await vaultModule.createKeyRing({
  namespace: "smoke",
  keys: [{ id: "k1", material: await vaultModule.generateKeyMaterial() }],
});
const keyed = vaultModule.createKeyedTokenizer({ keyring, vault: vaultModule.createMemoryVault() });
const token = await keyed.tokenize("alice@example.com", { category: "email", subject: "subject-1" });
assert.equal(await keyed.detokenize(token), "alice@example.com");
assert.equal((await keyed.forgetSubject("subject-1")).erased, 1);
assert.equal(await keyed.detokenize(token), undefined);
const sealed = vaultModule.createSealedTokenizer({ keyring });
assert.equal(
  await sealed.detokenize(await sealed.tokenize("bob@example.com", { category: "email" })),
  "bob@example.com",
);

// 5. Audit: a chain that verifies and holds no personal data.
const { createAuditLogger, memorySink, summarizeSpans, verifyAuditChain } = await import("anonyma/audit");
const sink = memorySink();
const audit = createAuditLogger({ sinks: [sink] });
await audit.record({ operation: "anonymize", fields: summarizeSpans(scrubbed.spans, { rule: "redact" }) });
assert.equal((await verifyAuditChain(sink.records())).ok, true);
assert.ok(!JSON.stringify(sink.records()).includes("alice"));

// 6. Compliance profiles, JSON and prompts, MCP, HTTP scrubbing.
const { REGULATIONS } = await import("anonyma/compliance");
assert.ok(REGULATIONS.gdpr !== undefined && REGULATIONS.lgpd !== undefined);

const { createLlmGuard, sanitizeJson } = await import("anonyma/ai");
assert.ok(!JSON.stringify(sanitizeJson({ email: "alice@example.com", n: 1 }, { pipeline }).value).includes("alice"));
const exchange = createLlmGuard().begin();
const { messages } = exchange.sanitizeMessages([{ role: "user", content: "Email alice@example.com" }]);
assert.equal(messages[0].content, "Email [EMAIL_0001]");
assert.equal(exchange.restoreText("Sent to [EMAIL_0001].").text, "Sent to alice@example.com.");

const { createMcpServer } = await import("anonyma/mcp");
assert.deepEqual(await createMcpServer().handle({ jsonrpc: "2.0", id: 1, method: "ping" }), {
  jsonrpc: "2.0",
  id: 1,
  result: {},
});

const { createScrubber } = await import("anonyma/middleware");
assert.ok(!JSON.stringify(createScrubber().json({ email: "alice@example.com" }, "smoke")).includes("alice"));

console.log("ESM: " + subpaths.length + " subpaths and the feature checks passed" + (withPeer ? " (with the optional peer)" : ""));
`;

const CJS_CHECK = `
const assert = require("node:assert/strict");
const { anonymize, AnonymaError } = require("anonyma");
const { compilePipeline } = require("anonyma/engine");
const { createSessionTokenizer } = require("anonyma/vault");

assert.ok(!anonymize("Mail alice@example.com").text.includes("alice"));
const session = createSessionTokenizer();
const pipeline = compilePipeline({ defaultStrategy: { strategy: "tokenize" } }, { tokenization: session });
assert.equal(session.restore(pipeline.transform("Email alice@example.com").text).text, "Email alice@example.com");
// One error class across entry points, in CommonJS too.
try {
  compilePipeline({ detection: "nope" });
  assert.fail("an invalid specification must be rejected");
} catch (error) {
  assert.ok(error instanceof AnonymaError, "entry points do not share the error class");
}
console.log("CJS: the feature checks passed");
`;

let failed = false;
try {
  console.log(`Node.js ${process.version} on ${process.platform}; project in ${project}`);
  writeFileSync(
    join(project, "package.json"),
    JSON.stringify({ name: "anonyma-smoke", private: true, type: "module" }),
  );
  writeFileSync(join(project, "check.mjs"), ESM_CHECK);
  writeFileSync(join(project, "check.cjs"), CJS_CHECK);

  const install = ["install", "--no-audit", "--no-fund", "--ignore-scripts", "--loglevel=error"];
  run(npm, [...install, tarballPath()]);
  run(process.execPath, ["check.mjs"]);
  run(process.execPath, ["check.cjs"]);

  // The optional peer dependency, for the one entry point that uses it.
  run(npm, [...install, "zod@^3.23.0"]);
  run(process.execPath, ["check.mjs", "--with-peer"]);
} catch (error) {
  failed = true;
  console.error(`\nSmoke test failed: ${error instanceof Error ? error.message : String(error)}`);
} finally {
  rmSync(project, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
