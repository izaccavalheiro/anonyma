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
