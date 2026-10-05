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

- `results/baseline.json` — anonyma 1.0.0 at commit `de26df2`.
- `results/current.json` — the build with the span engine; contains the 1.x functions and the engine from the same run.

Both were taken on Node v25.9.0, Intel Core i5-10400F, on an idle machine. Absolute numbers depend on the machine; compare ratios and slopes.
