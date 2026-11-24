/**
 * The benchmark results of bench/results, as tables with bars. Every number
 * is printed next to its bar, so the tables read without the bars.
 */

import Link from "@docusaurus/Link";
import type { ReactNode } from "react";
import baseline from "../../data/bench-baseline.json";
import current from "../../data/bench-current.json";
import styles from "./styles.module.css";

interface Row {
  readonly op: string;
  readonly size: number;
  readonly sizeLabel: string;
  readonly density: string;
  readonly medianMs: number;
  readonly p95Ms: number;
  readonly mbPerSec: number;
}

interface Results {
  readonly environment: { readonly node: string; readonly cpu: string; readonly cores: number };
  readonly results: readonly Row[];
  readonly scaling: readonly {
    readonly op: string;
    readonly density: string;
    readonly slope: number;
  }[];
  readonly perDetector: readonly {
    readonly category: string;
    readonly medianMs: number;
    readonly matches: number;
    readonly share: number;
  }[];
  readonly memory: {
    readonly perCall: readonly {
      readonly op: string;
      readonly size: number;
      readonly transientBytes: number;
      readonly retainedBytes: number;
    }[];
    readonly stream: {
      readonly bytes: number;
      readonly peakHeapGrowthBytes: number;
      readonly mbPerSec: number;
    };
  };
}

const now = current as unknown as Results;
const before = baseline as unknown as Results;

const number = (value: number, digits = 1): string =>
  value.toLocaleString("en-US", { maximumFractionDigits: digits, minimumFractionDigits: digits });

const bytes = (value: number): string =>
  value >= 1e6 ? `${number(value / 1e6)} MB` : `${number(value / 1e3, 0)} KB`;

interface BarRow {
  readonly key: string;
  readonly label: ReactNode;
  readonly value: number;
  readonly text: string;
  readonly detail?: string;
}

/** A table whose middle column is a bar proportional to the value. */
function BarTable(props: {
  readonly caption: string;
  readonly label: string;
  readonly unit: string;
  readonly rows: readonly BarRow[];
}): ReactNode {
  const max = Math.max(...props.rows.map((row) => row.value), Number.MIN_VALUE);
  return (
    <div className="table-wrap">
      <table className={styles["chart"]}>
        <caption className="sr-only">{props.caption}</caption>
        <thead>
          <tr>
            <th>{props.label}</th>
            <th aria-hidden="true" />
            <th className={styles["value"]}>{props.unit}</th>
          </tr>
        </thead>
        <tbody>
          {props.rows.map((row) => (
            <tr key={row.key} title={row.detail ?? `${String(row.label)}: ${row.text}`}>
              <td className={styles["label"]}>{row.label}</td>
              <td className={styles["track"]} aria-hidden="true">
                <div
                  className={styles["bar"]}
                  style={{ width: `${String((row.value / max) * 100)}%` }}
                />
              </td>
              <td className={styles["value"]}>{row.text}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function find(results: Results, op: string, sizeLabel: string, density: string): Row | undefined {
  return results.results.find(
    (r) => r.op === op && r.sizeLabel === sizeLabel && r.density === density,
  );
}

export default function Benchmarks(): ReactNode {
  const size = "100KB";
  // hasPII stops at the first value, so it is not a throughput: it is reported in a sentence.
  const quickCheck = find(now, "hasPII", size, "sparse");
  const throughput = now.results
    .filter((r) => r.sizeLabel === size && r.density === "sparse" && r.op !== "hasPII")
    .sort((a, b) => b.mbPerSec - a.mbPerSec);

  const transform = find(now, "engine/transform", size, "sparse");
  const legacy = find(before, "anonymize/redact", size, "sparse");
  const streamed = now.memory.stream;
  const engineScaling = now.scaling.filter((s) => s.op.startsWith("engine/"));
  const engineLinear = engineScaling.filter((s) => s.slope <= 1.1).length;
  const steepest = Math.max(...now.scaling.map((s) => s.slope));

  const compared = before.results
    .filter((r) => r.sizeLabel === size && r.density === "sparse")
    .map((old) => ({ old, fresh: find(now, old.op, size, "sparse") }))
    .filter((pair): pair is { old: Row; fresh: Row } => pair.fresh !== undefined);

  const memory = now.memory.perCall.filter((m) => m.size === 100_000);

  return (
    <>
      <p>
        Measured with <code>bench/run.mjs</code> on Node.js {now.environment.node},{" "}
        {now.environment.cpu} ({now.environment.cores} threads). Absolute numbers depend on the
        machine; compare ratios and slopes. Inputs are synthetic, with one value to replace per 200
        characters (&ldquo;sparse&rdquo;).{" "}
        <Link to="/docs/reference/benchmark-method">How it is measured</Link>.
      </p>

      <div className={styles["grid"]}>
        {transform === undefined ? null : (
          <div className={styles["tile"]}>
            <strong>{number(transform.mbPerSec)} MB/s</strong>
            <span className={styles["muted"]}>span engine, transform, {size}</span>
          </div>
        )}
        {legacy === undefined ? null : (
          <div className={styles["tile"]}>
            <strong>{number(legacy.mbPerSec)} MB/s</strong>
            <span className={styles["muted"]}>1.0 anonymize(), {size}</span>
          </div>
        )}
        <div className={styles["tile"]}>
          <strong>
            {engineLinear} of {engineScaling.length}
          </strong>
          <span className={styles["muted"]}>
            span-engine operations linear in input size (slope ≤ 1.1)
          </span>
        </div>
      </div>

      <h3>Throughput at {size}</h3>
      {quickCheck === undefined ? null : (
        <p>
          <code>hasPII()</code> stops at the first value it finds, so it is left out: on text with
          values it answers in {number(quickCheck.medianMs, 2)} ms.
        </p>
      )}
      <BarTable
        caption={`Throughput of each operation on ${size} of sparse text`}
        label="Operation"
        unit="MB/s"
        rows={throughput.map((r) => ({
          key: r.op,
          label: r.op,
          value: r.mbPerSec,
          text: number(r.mbPerSec),
          detail: `${r.op}: ${number(r.mbPerSec)} MB/s, median ${number(r.medianMs, 2)} ms, p95 ${number(r.p95Ms, 2)} ms`,
        }))}
      />

      <h3>Against 1.0</h3>
      <p>
        The same operations on the same inputs, in anonyma 1.0.0 and in the current build. A ratio
        above 1 is faster now.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Operation</th>
              <th>1.0 (MB/s)</th>
              <th>Now (MB/s)</th>
              <th>Ratio</th>
            </tr>
          </thead>
          <tbody>
            {compared.map(({ old, fresh }) => (
              <tr key={old.op}>
                <td>
                  <code>{old.op}</code>
                </td>
                <td>{number(old.mbPerSec)}</td>
                <td>{number(fresh.mbPerSec)}</td>
                <td>{number(fresh.mbPerSec / old.mbPerSec, 2)}×</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3>Cost of each detector</h3>
      <p>
        Time of each of the {now.perDetector.length} detectors on {size} of text with values of
        every kind.
      </p>
      <BarTable
        caption="Median time of each detector on 100 KB"
        label="Category"
        unit="ms"
        rows={[...now.perDetector]
          .sort((a, b) => b.medianMs - a.medianMs)
          .map((d) => ({
            key: d.category,
            label: d.category,
            value: d.medianMs,
            text: number(d.medianMs, 2),
            detail: `${d.category}: ${number(d.medianMs, 2)} ms, ${String(d.matches)} matches, ${number(d.share * 100)}% of the total`,
          }))}
      />

      <h3>Scaling</h3>
      <p>
        The slope of log(time) against log(size), from 100 B to 1 MB: 1.0 means the time grows in
        proportion to the input. The span engine stays linear; the 1.x <code>anonymize()</code>{" "}
        family grows faster on text with many values (up to {number(steepest, 2)}), which is one
        reason to compile a pipeline for large inputs.
      </p>
      <BarTable
        caption="Scaling slope of each operation"
        label="Operation (density)"
        unit="slope"
        rows={now.scaling.map((s) => ({
          key: `${s.op}/${s.density}`,
          label: `${s.op} (${s.density})`,
          value: s.slope,
          text: number(s.slope, 2),
        }))}
      />

      <h3>Memory</h3>
      <p>
        Heap growth during one call on 100 KB (garbage included), and what stays allocated after a
        collection. Streaming {bytes(streamed.bytes)} in line-sized chunks peaked at{" "}
        {bytes(streamed.peakHeapGrowthBytes)} of heap growth, at {number(streamed.mbPerSec)} MB/s.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Call</th>
              <th>During the call</th>
              <th>Retained</th>
            </tr>
          </thead>
          <tbody>
            {memory.map((m) => (
              <tr key={m.op}>
                <td>
                  <code>{m.op}</code>
                </td>
                <td>{bytes(m.transientBytes)}</td>
                <td>{bytes(Math.max(0, m.retainedBytes))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
