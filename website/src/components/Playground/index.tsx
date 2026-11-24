/**
 * The playground: text in, anonymized text out, with the findings, the vault
 * of reversible tokens and a receipt. Everything runs in the browser; values
 * are rendered as text, never as HTML.
 */

import { PRESET_REGISTRY } from "anonyma";
import type { CompliancePreset } from "anonyma";
import { createReceiptIssuer } from "anonyma/audit";
import { useCallback, useDeferredValue, useMemo, useState, type ReactNode } from "react";
import { SAMPLE, processText } from "./process";
import type { Mode, Outcome } from "./process";
import styles from "./styles.module.css";

const MODES: readonly (readonly [Mode, string])[] = [
  ["preset", "the presets' strategies (or redact)"],
  ["redact", "[REDACTED]"],
  ["mask", "a mask, last 4 kept"],
  ["pseudonymize", "a pseudonym"],
  ["synthesize", "synthetic values"],
  ["tokenize", "reversible tokens ({{EMAIL_1}})"],
];

const PRESETS = Object.keys(PRESET_REGISTRY) as CompliancePreset[];

/** A random key for this page only: receipts here show the format and prove nothing elsewhere. */
function pageKey(): string {
  return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(32)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function Output({ outcome }: { readonly outcome: Outcome }): ReactNode {
  const parts: ReactNode[] = [];
  let at = 0;
  outcome.findings.forEach((finding, index) => {
    parts.push(outcome.text.slice(at, finding.outStart));
    parts.push(
      <mark
        key={index}
        className={styles["mark"]}
        title={`${finding.category} (${finding.confidence.toFixed(2)})`}
      >
        {outcome.text.slice(finding.outStart, finding.outEnd)}
      </mark>,
    );
    at = finding.outEnd;
  });
  parts.push(outcome.text.slice(at));
  return (
    <pre className={styles["pane"]} aria-live="polite">
      {parts}
    </pre>
  );
}

export default function Playground(): ReactNode {
  const [text, setText] = useState(SAMPLE);
  const [presets, setPresets] = useState<CompliancePreset[]>([]);
  const [mode, setMode] = useState<Mode>("preset");
  const [validating, setValidating] = useState(true);
  const [receipt, setReceipt] = useState("");
  const [copied, setCopied] = useState(false);
  const key = useMemo(pageKey, []);
  const deferred = useDeferredValue(text);

  const result = useMemo((): Outcome | Error => {
    try {
      return processText(
        deferred,
        { presets, mode, detection: validating ? "precise" : "legacy" },
        () => performance.now(),
      );
    } catch (error) {
      return error instanceof Error ? error : new Error(String(error));
    }
  }, [deferred, presets, mode, validating]);

  const toggle = useCallback((preset: CompliancePreset) => {
    setReceipt("");
    setPresets((current) =>
      current.includes(preset) ? current.filter((p) => p !== preset) : [...current, preset],
    );
  }, []);

  const issue = useCallback(() => {
    if (result instanceof Error) return;
    createReceiptIssuer({ key, ...(presets.length > 0 ? { presets } : {}) })
      .issue({ text: result.text, spans: result.findings })
      .then((issued) => setReceipt(JSON.stringify(issued, null, 2)))
      .catch((error: unknown) => setReceipt(`Error: ${String(error)}`));
  }, [key, presets, result]);

  const copy = useCallback(() => {
    if (result instanceof Error) return;
    navigator.clipboard.writeText(result.text).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      },
      () => undefined,
    );
  }, [result]);

  const total = result instanceof Error ? 0 : result.findings.length;

  return (
    <div className={styles["playground"]}>
      <p className={styles["banner"]} role="note">
        <strong>Everything runs in your browser.</strong> The playground sends nothing you type to a
        server. The site&apos;s Content Security Policy forbids every network connection except to
        its analytics service, Monoid, which records page views and clicks.
      </p>

      <section className={styles["controls"]} aria-label="Settings">
        <fieldset className={styles["presets"]}>
          <legend>
            Presets <span className={styles["muted"]}>(several combine)</span>
          </legend>
          {PRESETS.map((preset) => (
            <label key={preset} title={PRESET_REGISTRY[preset].description}>
              <input
                type="checkbox"
                checked={presets.includes(preset)}
                onChange={() => toggle(preset)}
              />{" "}
              {preset.toUpperCase()}
            </label>
          ))}
        </fieldset>
        <label>
          Replace with{" "}
          <select
            value={mode}
            onChange={(event) => {
              setReceipt("");
              setMode(event.target.value as Mode);
            }}
          >
            {MODES.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label title="Check digits (CPF, IBAN, Luhn, …) must hold">
          <input
            type="checkbox"
            checked={validating}
            onChange={(event) => setValidating(event.target.checked)}
          />{" "}
          Validating detectors
        </label>
      </section>

      <section className={styles["panes"]}>
        <div className={styles["column"]}>
          <div className={styles["head"]}>
            <h2>
              <label htmlFor="playground-input">Your text</label>
            </h2>
            <span>
              <button
                type="button"
                className="button button--sm button--secondary"
                onClick={() => setText(SAMPLE)}
              >
                Sample
              </button>{" "}
              <button
                type="button"
                className="button button--sm button--secondary"
                onClick={() => setText("")}
              >
                Clear
              </button>
            </span>
          </div>
          <textarea
            id="playground-input"
            className={styles["pane"]}
            value={text}
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => {
              setReceipt("");
              setText(event.target.value);
            }}
          />
        </div>
        <div className={styles["column"]}>
          <div className={styles["head"]}>
            <h2>Output</h2>
            <button type="button" className="button button--sm button--secondary" onClick={copy}>
              {copied ? "Copied" : "Copy output"}
            </button>
          </div>
          {result instanceof Error ? (
            <pre className={styles["pane"]}>Error: {result.message}</pre>
          ) : (
            <Output outcome={result} />
          )}
        </div>
      </section>

      {result instanceof Error ? null : (
        <>
          <p className={styles["status"]} aria-live="polite">
            {total === 0
              ? `No personal data found (${result.millis.toFixed(1)} ms).`
              : `${String(total)} value${total === 1 ? "" : "s"} replaced in ${result.millis.toFixed(1)} ms.`}
          </p>
          <ul className={styles["counts"]} aria-label="Replaced values per category">
            {result.counts.map(([category, count]) => (
              <li key={category}>
                {category} {count}
              </li>
            ))}
          </ul>

          {result.vault === undefined ? null : (
            <section>
              <h2>Vault</h2>
              <p className={styles["muted"]}>
                The tokens stand for these values; the vault never left the page. Put back into the
                output:
              </p>
              <pre className={styles["small"]}>{result.restored}</pre>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Token</th>
                      <th>Original value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.vault.map(([token, value]) => (
                      <tr key={token}>
                        <td>
                          <code>{token}</code>
                        </td>
                        <td>
                          <code>{value}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <section>
            <h2>Findings</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>Found</th>
                    <th>Replaced by</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {result.findings.map((finding, index) => (
                    <tr key={index}>
                      <td>{finding.category}</td>
                      <td>
                        <code>{finding.value}</code>
                      </td>
                      <td>
                        <code>{finding.replacement}</code>
                      </td>
                      <td>{finding.confidence.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section>
            <h2>Receipt</h2>
            <p className={styles["muted"]}>
              A signed account of the run: categories, counts and a digest of the output, never a
              value. Here the key is made up for this page.
            </p>
            <button type="button" className="button button--primary" onClick={issue}>
              Issue a receipt
            </button>
            {receipt === "" ? null : <pre className={styles["small"]}>{receipt}</pre>}
          </section>
        </>
      )}
    </div>
  );
}
