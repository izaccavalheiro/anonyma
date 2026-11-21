/**
 * @module anonyma-cli/commands
 * @description `scrub` and `scan` for text, JSON Lines and CSV. Every format
 * is processed as a stream: memory use does not grow with the size of the
 * input.
 */

import { ValidationError } from "anonyma";
import { sanitizeJsonText, sanitizeJsonTextAsync } from "anonyma/ai";
import type { JsonSanitizeResult } from "anonyma/ai";
import { createAsyncChunkTransformer } from "anonyma/engine";
import type { DetectedSpan, Pipeline } from "anonyma/engine";
import { UsageError } from "./args.js";
import type { CliOptions } from "./args.js";
import { CsvReader, formatCsvRecord } from "./csv.js";
import type { CsvRecord } from "./csv.js";
import { lines } from "./io.js";
import type { Sink } from "./io.js";

/** Number of values per category. */
export type Tally = Map<string, number>;

/** One finding of `scan`: where, and what kind of data. Never the data itself. */
export interface Finding {
  /** Line number (text, JSON Lines) or record number (CSV), from 1. */
  readonly line: number;
  /** Column number (text), JSON Pointer (JSON Lines) or column name (CSV). */
  readonly where: string;
  readonly category: string;
  /** Number of values found there. */
  readonly count: number;
}

/** What a run went through. */
export interface Totals {
  /** Lines (text, JSON Lines) or records (CSV) read. */
  records: number;
  /** Lines or records with at least one value. */
  recordsWithPii: number;
  readonly tally: Tally;
}

/** Options shared by the format handlers. */
export interface RunContext {
  readonly options: CliOptions;
  readonly pipeline: Pipeline;
  /** Report a problem that does not stop the run, such as a line that is not JSON. */
  readonly warn: (message: string) => void;
}

function add(tally: Tally, category: string, count = 1): void {
  tally.set(category, (tally.get(category) ?? 0) + count);
}

function addSpans(tally: Tally, spans: readonly DetectedSpan[]): void {
  for (const span of spans) add(tally, span.category);
}

function addFields(tally: Tally, fields: JsonSanitizeResult<unknown>["fields"]): void {
  for (const field of fields) add(tally, field.category, field.count);
}

/** `true` for the error that sanitizeJsonText throws on text that is not JSON. */
function notJson(error: unknown): boolean {
  return error instanceof ValidationError && error.field === "text";
}

export function newTotals(): Totals {
  return { records: 0, recordsWithPii: 0, tally: new Map() };
}

// ---------------------------------------------------------------------------
// CSV columns
// ---------------------------------------------------------------------------

/**
 * The indices of the columns to process, or `undefined` for all of them.
 *
 * @throws {@link UsageError} When a column is not in the header or out of range.
 */
function selectColumns(
  wanted: readonly string[] | undefined,
  header: readonly string[] | undefined,
): Set<number> | undefined {
  if (wanted === undefined) return undefined;
  const names = header?.map((name, index) => (index === 0 ? name.replace(/^\uFEFF/, "") : name));
  const selected = new Set<number>();
  for (const column of wanted) {
    const byName = names?.findIndex((name) => name.trim().toLowerCase() === column.toLowerCase());
    if (byName !== undefined && byName !== -1) {
      selected.add(byName);
    } else if (/^\d+$/.test(column) && Number(column) >= 1) {
      selected.add(Number(column) - 1);
    } else {
      throw new UsageError(
        `No column "${column}" in the header${names === undefined ? "" : `: ${names.join(", ")}`}.`,
      );
    }
  }
  return selected;
}

/** The name of column `index` for a report: its header name, or its number. */
function columnName(index: number, header: readonly string[] | undefined): string {
  const name = header?.[index]?.replace(/^\uFEFF/, "").trim();
  return name === undefined || name === "" ? `column ${String(index + 1)}` : name;
}

/**
 * Read CSV records from `chunks` and hand each one to `each` with its number.
 * The header, when there is one, is passed with `isHeader`.
 */
async function eachRecord(
  chunks: AsyncIterable<string>,
  delimiter: string,
  each: (record: CsvRecord, number: number) => Promise<void>,
): Promise<void> {
  const reader = new CsvReader(delimiter);
  let number = 0;
  for await (const chunk of chunks) {
    for (const record of reader.push(chunk)) await each(record, ++number);
  }
  for (const record of reader.flush()) await each(record, ++number);
}

// ---------------------------------------------------------------------------
// scrub
// ---------------------------------------------------------------------------

/**
 * Replace the personal data in `input` and write the result to `sink`.
 *
 * @returns What was replaced.
 */
export async function scrub(
  input: AsyncIterable<string>,
  sink: Sink,
  context: RunContext,
): Promise<Totals> {
  const { options, pipeline, warn } = context;
  const totals = newTotals();
  const { tally } = totals;

  if (options.format === "txt") {
    // A value split between two chunks is still found: the transformer holds back a window.
    const counted: Pipeline = {
      ...pipeline,
      replace: (value, replaceContext) => {
        add(tally, replaceContext.category);
        return pipeline.replace(value, replaceContext);
      },
    };
    const transformer = createAsyncChunkTransformer(counted);
    for await (const chunk of input) await sink.write(await transformer.push(chunk));
    await sink.write(await transformer.flush());
    return totals;
  }

  if (options.format === "jsonl") {
    for await (const line of lines(input)) {
      totals.records++;
      const before = sum(tally);
      let text = line.text;
      if (text.trim() !== "") {
        try {
          const result = await sanitizeJsonTextAsync(text, { pipeline });
          addFields(tally, result.fields);
          text = result.text;
        } catch (error) {
          if (!notJson(error)) throw error;
          warn(`line ${String(totals.records)} is not JSON; it was scrubbed as text`);
          const result = await pipeline.transformAsync(text);
          addSpans(tally, result.spans);
          text = result.text;
        }
      }
      if (sum(tally) > before) totals.recordsWithPii++;
      await sink.write(text + line.eol);
    }
    return totals;
  }

  let header: string[] | undefined;
  let selected: Set<number> | undefined;
  await eachRecord(input, options.delimiter, async (record, number) => {
    if (number === 1) {
      if (options.header) header = record.fields;
      selected = selectColumns(options.columns, header);
      if (options.header) {
        await sink.write(formatCsvRecord(record, options.delimiter));
        return;
      }
    }
    totals.records++;
    const before = sum(tally);
    const fields = [...record.fields];
    for (const [index, value] of fields.entries()) {
      if (value === "" || (selected !== undefined && !selected.has(index))) continue;
      const result = await pipeline.transformAsync(value);
      addSpans(tally, result.spans);
      fields[index] = result.text;
    }
    if (sum(tally) > before) totals.recordsWithPii++;
    await sink.write(formatCsvRecord({ ...record, fields }, options.delimiter));
  });
  return totals;
}

function sum(tally: Tally): number {
  let total = 0;
  for (const count of tally.values()) total += count;
  return total;
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/**
 * Find the personal data in `input` without changing anything.
 *
 * @param found - Called with each finding, in the order of the input.
 * @returns What was found.
 */
export async function scan(
  input: AsyncIterable<string>,
  context: RunContext,
  found: (finding: Finding) => void,
): Promise<Totals> {
  const { options, pipeline, warn } = context;
  const totals = newTotals();
  const { tally } = totals;

  const scanText = (text: string, line: number): number => {
    const spans = pipeline.scan(text);
    for (const span of spans) {
      add(tally, span.category);
      found({ line, where: String(span.start + 1), category: span.category, count: 1 });
    }
    return spans.length;
  };

  if (options.format === "txt" || options.format === "jsonl") {
    for await (const line of lines(input)) {
      const number = ++totals.records;
      let count = 0;
      if (options.format === "txt") {
        count = scanText(line.text, number);
      } else if (line.text.trim() !== "") {
        try {
          const result = sanitizeJsonText(line.text, { pipeline });
          for (const field of result.fields) {
            add(tally, field.category, field.count);
            found({
              line: number,
              where: field.path,
              category: field.category,
              count: field.count,
            });
          }
          count = result.replaced;
        } catch (error) {
          if (!notJson(error)) throw error;
          warn(`line ${String(number)} is not JSON; it was scanned as text`);
          count = scanText(line.text, number);
        }
      }
      if (count > 0) totals.recordsWithPii++;
    }
    return totals;
  }

  let header: string[] | undefined;
  let selected: Set<number> | undefined;
  await eachRecord(input, options.delimiter, (record, number) => {
    if (number === 1) {
      if (options.header) header = record.fields;
      selected = selectColumns(options.columns, header);
      if (options.header) return Promise.resolve();
    }
    totals.records++;
    let count = 0;
    for (const [index, value] of record.fields.entries()) {
      if (value === "" || (selected !== undefined && !selected.has(index))) continue;
      for (const span of pipeline.scan(value)) {
        add(tally, span.category);
        found({
          line: number,
          where: columnName(index, header),
          category: span.category,
          count: 1,
        });
        count++;
      }
    }
    if (count > 0) totals.recordsWithPii++;
    return Promise.resolve();
  });
  return totals;
}
