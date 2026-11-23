/**
 * packages/sidecar/bench.mjs — where the time of a sidecar request goes.
 *
 * Splits one request of `POST /v1/detect` on a short entry into its parts, in
 * process: compiling the pipeline, scanning, and the whole route over
 * loopback HTTP. Needs the root build and the sidecar's (`npm run build` in
 * both).
 *
 *   node packages/sidecar/bench.mjs [--requests 2000]
 *
 * Every value is synthetic.
 */
import { Agent, createServer, request } from "node:http";
import { compilePipeline } from "anonyma/engine";
import { createSidecar } from "./dist/index.js";

const at = process.argv.indexOf("--requests");
const REQUESTS = at === -1 ? 2000 : Number(process.argv[at + 1]);

/** A log line of about 200 bytes with one email address. */
const ENTRY =
  "2026-11-23T10:00:07Z INFO request 000007 served for user7@example.com in 17 ms; " +
  "the cache was warm, the queue held 7 items and nothing else happened at all today.";

/** Median microseconds per call of `fn`, after a warm-up. */
function micros(fn, minimum = 2000) {
  for (let i = 0; i < 200; i++) fn();
  const samples = [];
  for (let round = 0; round < 7; round++) {
    const start = process.hrtime.bigint();
    for (let i = 0; i < minimum; i++) fn();
    samples.push(Number(process.hrtime.bigint() - start) / 1000 / minimum);
  }
  samples.sort((a, b) => a - b);
  return samples[3];
}

const rows = [];
const report = (name, us) => {
  rows.push({ name, us });
  console.log(`${name.padEnd(44)} ${us.toFixed(1).padStart(8)} µs`);
};

for (const [label, spec] of [
  ["{}", {}],
  ['{ preset: ["gdpr"] }', { preset: ["gdpr"] }],
  ['{ categories: ["email"] }', { categories: ["email"] }],
]) {
  report(
    `compilePipeline(${label})`,
    micros(() => compilePipeline(spec), 500),
  );
}
const pipeline = compilePipeline({});
report(
  "scan, 200 B, compiled once",
  micros(() => pipeline.scan(ENTRY), 500),
);
report(
  "compile + scan, 200 B",
  micros(() => compilePipeline({}).scan(ENTRY), 500),
);
report(
  "JSON.parse + stringify of a request",
  micros(() => JSON.parse(JSON.stringify({ text: ENTRY }))),
);

const sidecar = createSidecar({ mcp: false });
const server = createServer(sidecar.handle);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();
const post = (path, body) =>
  fetch(`http://127.0.0.1:${String(port)}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).then((response) => response.json());

// The same request with node:http and a keep-alive agent: a lighter client than fetch.
const agent = new Agent({ keepAlive: true, maxSockets: 1 });
const postRaw = (path, body) =>
  new Promise((resolve, reject) => {
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
        response.on("end", () => resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))));
      },
    );
    call.on("error", reject);
    call.end(payload);
  });

async function perRequest(path, body, send = post) {
  for (let i = 0; i < 200; i++) await send(path, body);
  const start = process.hrtime.bigint();
  for (let i = 0; i < REQUESTS; i++) await send(path, body);
  return Number(process.hrtime.bigint() - start) / 1000 / REQUESTS;
}

const answer = await post("/v1/detect", { text: ENTRY });
if (answer.matches?.length !== 1) throw new Error(`unexpected answer ${JSON.stringify(answer)}`);
report("POST /v1/detect, 200 B, loopback", await perRequest("/v1/detect", { text: ENTRY }));
report("POST /v1/anonymize, 200 B, loopback", await perRequest("/v1/anonymize", { text: ENTRY }));
report("POST /v1/detect, empty text, loopback", await perRequest("/v1/detect", { text: "" }));
report(
  "POST /v1/detect, 200 B, node:http keep-alive",
  await perRequest("/v1/detect", { text: ENTRY }, postRaw),
);
report(
  "POST /v1/detect, empty text, node:http keep-alive",
  await perRequest("/v1/detect", { text: "" }, postRaw),
);
// Batches: microseconds per text, 1,000 texts per request.
const batch = Array.from({ length: 1000 }, () => ENTRY);
for (const path of ["/v1/detect/batch", "/v1/anonymize/batch"]) {
  const reply = await postRaw(path, { texts: batch });
  if (reply.results?.length !== batch.length) throw new Error(`unexpected answer from ${path}`);
  for (let i = 0; i < 3; i++) await postRaw(path, { texts: batch });
  const rounds = 10;
  const start = process.hrtime.bigint();
  for (let i = 0; i < rounds; i++) await postRaw(path, { texts: batch });
  const perText = Number(process.hrtime.bigint() - start) / 1000 / rounds / batch.length;
  report(`POST ${path}, 1,000 × 200 B, per text`, perText);
}
agent.destroy();
server.close();
