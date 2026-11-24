/**
 * The benchmark matrix of bench/results (matrix.json, model.json): every engine
 * anonyma runs on, timed on the same corpus through the API its users call.
 */

import Link from "@docusaurus/Link";
import type { ReactNode } from "react";
import matrix from "../../data/bench-matrix.json";
import model from "../../data/bench-model.json";

interface MatrixRow {
  readonly engine: string;
  readonly op: string;
  readonly shape: "single" | "each" | "batch";
  readonly entrySize: number;
  readonly entries: number;
  readonly threads: number;
  readonly medianMs: number;
  readonly perEntryUs: number;
}

interface EngineModel {
  readonly op: string;
  readonly cCallUs: number | null;
  readonly cByteNs: number | null;
  readonly exponent: number | null;
  readonly maxRelativeError: number | null;
  readonly batchSpeedup: number | null;
  readonly fasterThanTsFromBytes: number | null;
  readonly threads: readonly {
    readonly threads: number;
    readonly speedup: number;
    readonly efficiency: number;
  }[];
}

interface Environment {
  readonly cpu: string;
  readonly threads: number;
  readonly os: string;
  readonly date: string;
}

const rows = (matrix as unknown as { readonly rows: readonly MatrixRow[] }).rows;
const { environment, engines } = model as unknown as {
  readonly environment: Environment;
  readonly engines: Readonly<Record<string, EngineModel>>;
};

/** What each engine is, in the words of its users. */
const LABELS: Readonly<Record<string, string>> = {
  ts: "TypeScript (anonyma)",
  "ts-pool": "TypeScript, worker pool (anonyma-parallel)",
  rust: "Rust core",
  python: "Python",
  go: "Go",
  sidecar: "Sidecar (HTTP over loopback)",
};
const ORDER = ["ts", "ts-pool", "rust", "python", "go", "sidecar"];
const names = ORDER.filter((name) => name in engines);

const number = (value: number | null | undefined, digits = 1): string =>
  value === null || value === undefined
    ? "—"
    : value.toLocaleString("en-US", {
        maximumFractionDigits: digits,
        minimumFractionDigits: digits,
      });

const cell = (engine: string, shape: MatrixRow["shape"], size?: number): MatrixRow | undefined =>
  rows.find(
    (r) =>
      r.engine === engine &&
      r.shape === shape &&
      (shape !== "each" || r.threads === 1) &&
      (size === undefined || r.entrySize === size),
  );

const sizes = [...new Set(rows.filter((r) => r.shape === "single").map((r) => r.entrySize))].sort(
  (a, b) => a - b,
);
const sizeLabel = (bytes: number): string =>
  bytes >= 1e6 ? `${number(bytes / 1e6, 0)} MB` : `${number(bytes / 1e3, 0)} KB`;

export default function Engines(): ReactNode {
  const each = cell("ts", "each");
  const lines =
    each === undefined
      ? ""
      : `${number(each.entries, 0)} lines of about ${String(each.entrySize)} bytes`;
  const pool = rows.filter((r) => r.engine === "ts-pool").sort((a, b) => a.threads - b.threads);
  const tsBatch = cell("ts", "batch");
  return (
    <>
      <p>
        Every engine anonyma runs on, timed on the same synthetic corpus through the call its users
        make: one text of each size, {lines} called one by one, and the same lines in one batch
        call. Measured {environment.date} on {environment.cpu} ({environment.threads} threads),{" "}
        {environment.os}. Every engine that runs <code>detect</code> found the same values as
        TypeScript; the sidecar runs the span engine (<code>scan</code>).{" "}
        <Link to="/docs/reference/benchmark-method">How it is measured</Link>.
      </p>

      <div className="table-wrap">
        <table>
          <caption className="sr-only">Time of each engine per text size and per line</caption>
          <thead>
            <tr>
              <th>Engine</th>
              {sizes.map((s) => (
                <th key={s}>{sizeLabel(s)} (ms)</th>
              ))}
              <th>Line, one by one (µs)</th>
              <th>Line, in a batch (µs)</th>
            </tr>
          </thead>
          <tbody>
            {names.map((name) => (
              <tr key={name}>
                <td>{LABELS[name] ?? name}</td>
                {sizes.map((s) => (
                  <td key={s}>{number(cell(name, "single", s)?.medianMs, 2)}</td>
                ))}
                <td>{number(cell(name, "each")?.perEntryUs)}</td>
                <td>{number(cell(name, "batch")?.perEntryUs)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3>The cost of a call</h3>
      <p>
        Fitted per engine on the rows above: a call on a text of <em>s</em> bytes costs about{" "}
        <code>C_call + C_byte × s^k</code>. <code>C_call</code> is what every call pays before it
        reads a byte; it is why a batch helps short texts most. The last column is the text size
        from which an engine costs less than TypeScript.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Engine</th>
              <th>C_call (µs)</th>
              <th>C_byte (ns)</th>
              <th>k</th>
              <th>Fit error</th>
              <th>Faster than TypeScript from</th>
            </tr>
          </thead>
          <tbody>
            {names
              .filter((name) => engines[name]?.cCallUs !== null)
              .map((name) => {
                const m = engines[name];
                const from = m?.fasterThanTsFromBytes ?? null;
                return (
                  <tr key={name}>
                    <td>{LABELS[name] ?? name}</td>
                    <td>{number(m?.cCallUs)}</td>
                    <td>{number(m?.cByteNs)}</td>
                    <td>{number(m?.exponent, 2)}</td>
                    <td>
                      {m?.maxRelativeError === null || m?.maxRelativeError === undefined
                        ? "—"
                        : `${number(m.maxRelativeError * 100, 0)}%`}
                    </td>
                    <td>{name === "ts" ? "—" : from === null ? "never" : `${String(from)} B`}</td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      <h3>More threads</h3>
      <p>
        The Rust core, Python and Go engines are safe for concurrent use: the lines called one by
        one from several threads at once. The worker pool runs batches, against{" "}
        <code>detectBatch()</code> in one thread
        {tsBatch === undefined ? "" : ` (${number(tsBatch.perEntryUs)} µs a line)`}. Efficiency is
        the speed-up divided by the threads; the machine has fewer cores than threads.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Engine</th>
              <th>Threads</th>
              <th>Speed-up</th>
              <th>Efficiency</th>
            </tr>
          </thead>
          <tbody>
            {names.flatMap((name) =>
              (engines[name]?.threads ?? []).map((t) => (
                <tr key={`${name}/${String(t.threads)}`}>
                  <td>{LABELS[name] ?? name}</td>
                  <td>{t.threads}</td>
                  <td>{number(t.speedup, 2)}×</td>
                  <td>{number(t.efficiency, 2)}</td>
                </tr>
              )),
            )}
          </tbody>
        </table>
      </div>
      {pool.length === 0 ? null : (
        <p>
          On the pool, a line costs{" "}
          {pool
            .map((r) => `${number(r.perEntryUs)} µs with ${String(r.threads)} workers`)
            .join(", ")}
          . Batches under 8 KB run in the calling thread.{" "}
          <Link to="/docs/guides/speed-and-batches">Which call to use</Link>.
        </p>
      )}
    </>
  );
}
