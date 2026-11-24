#!/usr/bin/env node
/**
 * bench/matrix/sidecar.mjs — the sidecar's cells of the benchmark matrix, over
 * loopback with a keep-alive node:http client, on the built sidecar
 * (npm run build at the root and in packages/sidecar).
 *
 *   node bench/matrix/sidecar.mjs <corpus dir> <out.jsonl>
 *
 * The sidecar runs the span engine (precise detection), so its rows have
 * `op: "scan"`; their matches are not compared with `detect`'s.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { Agent, createServer, request } from "node:http";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const [dir, out] = process.argv.slice(2);
if (dir === undefined || out === undefined) {
  console.error("usage: node bench/matrix/sidecar.mjs <corpus dir> <out.jsonl>");
  process.exit(2);
}
const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const { createSidecar } = await import(
  pathToFileURL(join(root, "packages", "sidecar", "dist", "index.js")).href
);

const sidecar = createSidecar({ mcp: false, maxBodyBytes: 8 * 1024 * 1024 });
const server = createServer(sidecar.handle);
await new Promise((ready) => server.listen(0, "127.0.0.1", ready));
const { port } = server.address();
const agent = new Agent({ keepAlive: true, maxSockets: 1 });

const post = (path, body) =>
  new Promise((done, fail) => {
    const payload = JSON.stringify(body);
    const call = request(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        agent,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
        },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => done(JSON.parse(Buffer.concat(chunks).toString("utf8"))));
      },
    );
    call.on("error", fail);
    call.end(payload);
  });

/** Median milliseconds of one run of `run`, over at least 3 runs and 300 ms. */
async function median(run) {
  await run();
  const samples = [];
  const start = performance.now();
  while (samples.length < 3 || (performance.now() - start < 300 && samples.length < 50)) {
    const t = performance.now();
    await run();
    samples.push(performance.now() - t);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)];
}

const rows = [];
const row = (fields) => {
  rows.push({
    engine: "sidecar",
    runtime: `node ${process.versions.node}, HTTP loopback`,
    op: "scan",
    threads: 1,
    ...fields,
    perEntryUs: (fields.medianMs * 1000) / fields.entries,
  });
  console.log(JSON.stringify(rows.at(-1)));
};

for (const name of ["1k", "100k", "1m"]) {
  const text = readFileSync(join(dir, `single-${name}.txt`), "utf8");
  const { matches } = await post("/v1/detect", { text });
  const medianMs = await median(() => post("/v1/detect", { text }));
  row({ shape: "single", entrySize: text.length, entries: 1, medianMs, matches: matches.length });
}

const entries = JSON.parse(readFileSync(join(dir, "entries.json"), "utf8"));
const entrySize = Math.round(entries.reduce((n, e) => n + e.length, 0) / entries.length);
let each = 0;
for (const text of entries) each += (await post("/v1/detect", { text })).matches.length;
row({
  shape: "each",
  entrySize,
  entries: entries.length,
  medianMs: await median(async () => {
    for (const text of entries) await post("/v1/detect", { text });
  }),
  matches: each,
});

// Batches of 1,000 texts per request.
const groups = [];
for (let i = 0; i < entries.length; i += 1000) groups.push(entries.slice(i, i + 1000));
let batch = 0;
for (const texts of groups) {
  for (const result of (await post("/v1/detect/batch", { texts })).results)
    batch += result.matches.length;
}
row({
  shape: "batch",
  entrySize,
  entries: entries.length,
  medianMs: await median(async () => {
    for (const texts of groups) await post("/v1/detect/batch", { texts });
  }),
  matches: batch,
});

agent.destroy();
server.close();
writeFileSync(out, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
