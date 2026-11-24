# Benchmark

`run.mjs` measures a **built** package, so the same script compares builds on identical inputs. It has no dependencies. `corpus.mjs` generates the inputs as a pure function of size, density and seed; every planted value is synthetic (`example.com` addresses, documentation IP ranges, test card numbers).

```bash
npm run build
npm run bench -- --quick                              # about 30 seconds, sizes up to 100 KB
npm run bench                                         # full matrix, several minutes
npm run bench -- --json bench/results/current.json    # save every number
node bench/run.mjs --dist /path/to/other/dist         # measure another build
node bench/run.mjs --filter engine                    # only operations whose name contains "engine"
```

## What is measured

- **Latency and throughput** — median and 95th percentile per call, operations per second and MB/s, for the 1.x functions and, when the build has `anonyma/engine`, for the pipeline and the chunk transformer. Sizes 100 B to 1 MB; no personal data, one item per 200 characters, one per 40.
- **Scaling** — the least-squares slope of log(time) against log(size); 1.0 is linear. Also time against the number of matches at a fixed size.
- **Per-detector cost** — each of the 27 detectors on 100 KB.
- **Memory** — in a child process with `--expose-gc`: heap growth during one call (measured right after the call, so it includes garbage the call left; a lower bound if a scavenge ran during the call), retained heap after a collection, and peak heap while streaming 50 MB in line-sized chunks.

Each cell is warmed up once and then sampled for at least 300 ms and 5 iterations.

## Results

- `results/baseline.json` — anonyma 1.0.0, the package published on npm (`--dist` pointed at its `dist`).
- `results/current.json` — anonyma 1.5.1: the 1.x functions, the span engine, the batch functions and
  the label-heavy cells, from the same run.

Both were taken one after the other on the same machine: Node v26.13.1, Intel Core i5-8265U (4 cores,
8 threads), Windows 11, a laptop whose clock varies with heat. Absolute numbers depend on the
machine; compare ratios and slopes.

## The Rust core

`bench/core.mjs` times the same operations (detect, scan, anonymize with a preset)
on the TypeScript build and on the Rust core, through its Node.js addon (napi-rs)
and its WebAssembly build (wasm-bindgen; the engine Cloudflare Workers would run,
on the same V8). The core is called through its JSON API, so its timings include
serializing the input and parsing the answer. Before timing, it checks that both
Rust engines return TypeScript's results on every input up to 100,000 characters.

It needs a Rust toolchain, so it runs in the "Core benchmark" workflow
(`.github/workflows/core-bench.yml`), by hand from the Actions tab or when the
script changes; the tables are in the job summary.

```sh
node bench/core.mjs --native anonyma_native.node --wasm pkg/anonyma_wasm.js [--quick]
```

`results/core.json` is the run that settled step 4 of the RFC: GitHub's
`ubuntu-24.04` runner, Node.js 24, AMD EPYC 7763 (4 cores). The npm package
keeps its TypeScript engine; docs/rfcs/0001-polyglot-core.md has the summary.

## The matrix: every engine, one corpus

`bench/matrix/` times every engine anonyma runs on, on the same bytes, through the API its users
call:

| Engine    | Harness                                         | Batch call                               |
| --------- | ----------------------------------------------- | ---------------------------------------- |
| `ts`      | `bench/matrix/ts.mjs` (the built package)       | `detectBatch()`                          |
| `ts-pool` | `bench/matrix/ts-pool.mjs` (anonyma-parallel)   | `pool.detectBatch()`, 2, 4, every core   |
| `rust`    | `crates/anonyma-core/examples/matrix.rs`        | `detect_batch()`, rayon                  |
| `python`  | `bindings/python/bench/matrix.py`               | `detect_batch()`, GIL released, rayon    |
| `go`      | `bindings/go/internal/matrix` (`go run`)        | `Engine.DetectBatch()`, rayon            |
| `sidecar` | `bench/matrix/sidecar.mjs` (HTTP over loopback) | `POST /v1/detect/batch`, 1,000 a request |

```sh
node bench/matrix/corpus.mjs <dir>/corpus          # the texts every harness reads
node bench/matrix/ts.mjs <dir>/corpus <dir>/rows/ts.jsonl
# ... one harness per engine, each writing <dir>/rows/<engine>.jsonl
node bench/matrix/merge.mjs <dir>/rows bench/results
```

Each harness times the same cells: one text of 1 KB, 100 KB and 1 MB; 10,000 log lines of about
200 bytes called one by one; and the same lines through the batch call. The Rust, Python and Go harnesses also call the lines one by one
from 2, 4 and every hardware thread at once (their engines are safe for concurrent use); the pool
runs batches only, one row per pool size. Every row has the same
fields (`engine`, `op`, `shape`, `entrySize`, `entries`, `threads`, `medianMs`, `perEntryUs`,
`matches`).

`merge.mjs` writes `results/matrix.json` (every row, and any cell where an engine running `detect`
reports other matches than TypeScript) and `results/model.json`. The model fits, per engine,
`T(s) = C_call + C_byte × s^k`, the cost of a call on a text of `s` bytes, by least squares on the
relative error over the rows on one thread, with `k` searched from 0.7 to 1.5 (small texts stay in
cache, so the cost per byte grows with size). The rows on more threads give each engine's speed-up
and parallel efficiency; the pool's are against TypeScript's batch on one thread. The text size from which an engine beats TypeScript follows from it. The sidecar
runs the span engine (`op: "scan"`), so its matches are not compared with `detect`'s.

The "Benchmark matrix" workflow (`.github/workflows/bench-matrix.yml`) runs the matrix on Linux and
macOS by hand, weekly, and when a harness changes, with the tables in the job summary and the JSON
files as an artifact. A difference in results fails it; timings never do.
