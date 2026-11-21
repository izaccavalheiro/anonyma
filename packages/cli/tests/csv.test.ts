import { describe, expect, it } from "vitest";
import { CsvReader, formatCsvRecord } from "../src/csv.js";
import type { CsvRecord } from "../src/csv.js";

/** Read `text` in pieces of `size` characters. */
function read(text: string, size = text.length, delimiter = ","): CsvRecord[] {
  const reader = new CsvReader(delimiter);
  const out: CsvRecord[] = [];
  for (let at = 0; at < text.length; at += size)
    out.push(...reader.push(text.slice(at, at + size)));
  out.push(...reader.flush());
  return out;
}

function roundTrip(text: string, size?: number, delimiter = ","): string {
  return read(text, size, delimiter)
    .map((record) => formatCsvRecord(record, delimiter))
    .join("");
}

const SAMPLES = [
  "a,b,c\n1,2,3\n",
  "a,b\r\n1,2\r\n",
  "a,b\r1,2\r",
  'name,note\nAna,"hello, world"\nBob,"say ""hi"""\n',
  'name,note\nAna,"multi\nline"\nBob,"cr\r\nlf"\n',
  "a,b\n\n1,2\n",
  "a,b\n1,2",
  '"only"',
  '""',
  "a,,c\n,,\n",
  "\uFEFFname,email\nAna,ana@example.com\n",
];

describe("CsvReader", () => {
  it.each(SAMPLES)("round-trips %j exactly, in chunks of any size", (sample) => {
    for (const size of [1, 2, 3, 7, sample.length]) {
      expect(roundTrip(sample, size)).toBe(sample);
    }
  });

  it("unquotes fields and records which were quoted", () => {
    const [header, row] = read('name,note\nAna,"say ""hi"", ok"\n');
    expect(header?.fields).toEqual(["name", "note"]);
    expect(row).toEqual({ fields: ["Ana", 'say "hi", ok'], quoted: [false, true], eol: "\n" });
  });

  it("keeps each record's line ending", () => {
    expect(read("a\r\nb\nc\rd").map((record) => record.eol)).toEqual(["\r\n", "\n", "\r", ""]);
  });

  it("keeps a stray quote as text, and writes the record back as valid CSV", () => {
    expect(read('ab"c,"x"y\n')[0]?.fields).toEqual(['ab"c', "xy"]);
    expect(roundTrip('ab"c,"x"y\n', 1)).toBe('"ab""c","xy"\n');
  });

  it("returns nothing for empty input", () => {
    expect(read("")).toEqual([]);
  });

  it("reads other delimiters", () => {
    expect(read("a\tb\n1\t2\n", undefined, "\t").map((record) => record.fields)).toEqual([
      ["a", "b"],
      ["1", "2"],
    ]);
    expect(roundTrip('a;b\n1;"x;y"\n', 2, ";")).toBe('a;b\n1;"x;y"\n');
  });

  it("rejects a delimiter that cannot work", () => {
    for (const delimiter of ["", ",,", '"', "\n", "\r"]) {
      expect(() => new CsvReader(delimiter)).toThrow(/delimiter/);
    }
  });
});

describe("formatCsvRecord", () => {
  it("quotes a value that now holds a delimiter, quote or line break", () => {
    const record: CsvRecord = {
      fields: ["a,b", 'say "x"', "l\nm", "c\rd", "plain"],
      quoted: [],
      eol: "\n",
    };
    expect(formatCsvRecord(record, ",")).toBe('"a,b","say ""x""","l\nm","c\rd",plain\n');
  });
});
