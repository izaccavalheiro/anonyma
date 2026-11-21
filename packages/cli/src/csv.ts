/**
 * @module anonyma-cli/csv
 * @description A streaming CSV reader and writer (RFC 4180) that round-trips a
 * file exactly: each record keeps its own line ending, and each field whether
 * it was quoted. Fields may hold delimiters, quotes and line breaks.
 */

/** One CSV record. */
export interface CsvRecord {
  /** The values of the fields, unquoted. */
  readonly fields: string[];
  /** Whether each field was quoted in the input. */
  readonly quoted: boolean[];
  /** The line ending after the record: `"\r\n"`, `"\n"`, `"\r"`, or `""` for the last record of a file without one. */
  readonly eol: string;
}

const QUOTE = 34;
const LF = 10;
const CR = 13;

/**
 * Reads CSV text that arrives in chunks of any size and returns the records
 * that are complete.
 *
 * A quote inside an unquoted field, or after the closing quote of a quoted
 * field, is kept as text: such files are malformed, but their content must
 * still be scanned rather than rejected.
 */
export class CsvReader {
  readonly #delimiter: number;
  #fields: string[] = [];
  #quoted: boolean[] = [];
  #field = "";
  #fieldQuoted = false;
  /** Inside a quoted field. */
  #inQuotes = false;
  /** Just read a quote inside a quoted field: an escaped quote or the end of the field. */
  #quotePending = false;
  /** Just read a carriage return outside quotes: the end of a record, `\r` or `\r\n`. */
  #crPending = false;
  /** Whether anything of the current record has been read. */
  #started = false;

  /**
   * @param delimiter - The field delimiter, a single character.
   */
  public constructor(delimiter: string) {
    if (delimiter.length !== 1 || delimiter === '"' || delimiter === "\n" || delimiter === "\r") {
      throw new Error(
        "The CSV delimiter must be one character other than a quote or a line break.",
      );
    }
    this.#delimiter = delimiter.charCodeAt(0);
  }

  #endField(): void {
    this.#fields.push(this.#field);
    this.#quoted.push(this.#fieldQuoted);
    this.#field = "";
    this.#fieldQuoted = false;
  }

  #endRecord(eol: string, out: CsvRecord[]): void {
    this.#endField();
    out.push({ fields: this.#fields, quoted: this.#quoted, eol });
    this.#fields = [];
    this.#quoted = [];
    this.#started = false;
  }

  /**
   * Read the next chunk.
   *
   * @returns The records completed by this chunk.
   */
  public push(chunk: string): CsvRecord[] {
    const out: CsvRecord[] = [];
    let plainStart = -1;
    const flushPlain = (end: number): void => {
      if (plainStart !== -1) {
        this.#field += chunk.slice(plainStart, end);
        plainStart = -1;
      }
    };
    for (let at = 0; at < chunk.length; at++) {
      const code = chunk.charCodeAt(at);
      if (this.#crPending) {
        this.#crPending = false;
        if (code === LF) {
          this.#endRecord("\r\n", out);
          continue;
        }
        this.#endRecord("\r", out);
      }
      if (this.#quotePending) {
        this.#quotePending = false;
        if (code === QUOTE) {
          this.#field += '"';
          continue;
        }
        this.#inQuotes = false;
      }
      if (this.#inQuotes) {
        if (code === QUOTE) {
          flushPlain(at);
          this.#quotePending = true;
        } else if (plainStart === -1) {
          plainStart = at;
        }
        continue;
      }
      if (code === this.#delimiter) {
        flushPlain(at);
        this.#endField();
        this.#started = true;
      } else if (code === LF) {
        flushPlain(at);
        this.#endRecord("\n", out);
      } else if (code === CR) {
        flushPlain(at);
        this.#crPending = true;
      } else if (code === QUOTE && this.#field === "" && plainStart === -1 && !this.#fieldQuoted) {
        this.#inQuotes = true;
        this.#fieldQuoted = true;
        this.#started = true;
      } else {
        if (plainStart === -1) plainStart = at;
        this.#started = true;
      }
    }
    flushPlain(chunk.length);
    return out;
  }

  /**
   * Signal the end of the input.
   *
   * @returns The last record, when the input did not end with a line break.
   */
  public flush(): CsvRecord[] {
    const out: CsvRecord[] = [];
    if (this.#crPending) {
      this.#crPending = false;
      this.#endRecord("\r", out);
      return out;
    }
    this.#quotePending = false;
    this.#inQuotes = false;
    if (this.#started || this.#field !== "" || this.#fieldQuoted) this.#endRecord("", out);
    return out;
  }
}

/**
 * Write a record as CSV. A field is quoted when it was quoted in the input or
 * when its value now needs quotes: it holds the delimiter, a quote or a line
 * break.
 *
 * @param record - The record, with its fields replaced as needed.
 * @param delimiter - The field delimiter.
 * @returns The CSV text of the record, line ending included.
 */
export function formatCsvRecord(record: CsvRecord, delimiter: string): string {
  const parts = record.fields.map((value, index) => {
    const needsQuotes =
      record.quoted[index] === true ||
      value.includes(delimiter) ||
      value.includes('"') ||
      value.includes("\n") ||
      value.includes("\r");
    return needsQuotes ? `"${value.replaceAll('"', '""')}"` : value;
  });
  return parts.join(delimiter) + record.eol;
}
