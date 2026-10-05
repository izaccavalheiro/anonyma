/**
 * @module audit/sinks
 * @description Sinks for sealed audit records.
 */

import { canonicalize } from "./canonical.js";
import type { AuditRecord, AuditSink } from "./types.js";

/**
 * An {@link AuditSink} that keeps records in memory.
 */
export interface MemoryAuditSink extends AuditSink {
  /** The records appended so far, in chain order. */
  readonly records: () => readonly AuditRecord[];
}

/**
 * Create a sink that keeps records in memory. Useful for tests and for
 * handing a batch of records to another system.
 *
 * @returns The sink.
 *
 * @example
 * ```ts
 * const sink = memorySink();
 * const audit = createAuditLogger({ sinks: [sink] });
 * await audit.record({ operation: "detect", fields: [] });
 * sink.records().length; // 1
 * ```
 */
export function memorySink(): MemoryAuditSink {
  const records: AuditRecord[] = [];
  return Object.freeze({
    append(record: AuditRecord): void {
      records.push(record);
    },
    records: (): readonly AuditRecord[] => [...records],
  });
}

/**
 * Create a sink that writes each record as one line of canonical JSON
 * (NDJSON). The `write` function decides where lines go, which keeps this
 * module free of file-system and network code.
 *
 * @param write - Receives one line, including the trailing line feed. It must only append.
 * @returns The sink.
 *
 * @example
 * ```ts
 * import { appendFile } from "node:fs/promises";
 *
 * const sink = lineSink((line) => appendFile("/var/log/anonyma/audit.ndjson", line));
 * ```
 */
export function lineSink(write: (line: string) => void | Promise<void>): AuditSink {
  return Object.freeze({
    append: (record: AuditRecord): void | Promise<void> => write(`${canonicalize(record)}\n`),
  });
}

/**
 * Parse an NDJSON audit log into records for {@link verifyAuditChain}. Blank
 * lines are skipped. A line that is not valid JSON, or not the canonical JSON
 * the logger writes (reordered or duplicate members, extra whitespace),
 * becomes `null`, which the verifier reports as malformed at that position:
 * the stored text must say exactly what the verified record says.
 *
 * @param text - The log text.
 * @returns One entry per non-blank line.
 *
 * @example
 * ```ts
 * const result = await verifyAuditChain(parseAuditLog(await readFile("audit.ndjson", "utf8")));
 * ```
 */
export function parseAuditLog(text: string): unknown[] {
  const out: unknown[] = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    const stored = line.endsWith("\r") ? line.slice(0, -1) : line;
    try {
      const parsed = JSON.parse(stored) as unknown;
      out.push(canonicalize(parsed) === stored ? parsed : null);
    } catch {
      out.push(null);
    }
  }
  return out;
}
