import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { gunzipSync, gzipSync } from "node:zlib";
import { createReceiptIssuer } from "anonyma/audit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { formatOf, parseCommandLine } from "../src/args.js";
import { lines } from "../src/io.js";
import { CLI_VERSION, run } from "../src/index.js";

const KEY = "cli-test-receipt-key-0123456789abcdef";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "anonyma-cli-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

class Collect extends Writable {
  public text = "";
  public override _write(chunk: Buffer, _encoding: string, done: () => void): void {
    this.text += chunk.toString("utf8");
    done();
  }
}

interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

async function cli(
  args: string[],
  stdin: string | Buffer = "",
  env: Record<string, string> = {},
): Promise<Result> {
  const stdout = new Collect();
  const stderr = new Collect();
  const code = await run(args, {
    stdin: Readable.from([typeof stdin === "string" ? Buffer.from(stdin) : stdin]),
    stdout,
    stderr,
    env,
  });
  return { code, stdout: stdout.text, stderr: stderr.text };
}

async function file(name: string, content: string | Buffer): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, content);
  return path;
}

const LOG = "[info] login ana@example.com from 192.0.2.10\n[info] ok\ncard 4111 1111 1111 1111\n";

describe("anonyma scrub", () => {
  it("scrubs text from standard input to standard output", async () => {
    const result = await cli(["scrub"], LOG);
    expect(result.code).toBe(0);
    expect(result.stdout).toBe(
      "[info] login [REDACTED] from [REDACTED]\n[info] ok\ncard [REDACTED]\n",
    );
    expect(result.stderr).toMatch(/replaced 3 values \(.*email 1.*\)/);
  });

  it("finds a value split between chunks of the input", async () => {
    const stdout = new Collect();
    const code = await run(["scrub", "-q"], {
      stdin: Readable.from([Buffer.from("mail ana@exa"), Buffer.from("mple.com now")]),
      stdout,
      stderr: new Collect(),
      env: {},
    });
    expect(code).toBe(0);
    expect(stdout.text).toBe("mail [REDACTED] now");
  });

  it("decodes a character split between chunks", async () => {
    const bytes = Buffer.from("José ana@example.com");
    const stdout = new Collect();
    await run(["scrub", "-q"], {
      stdin: Readable.from([bytes.subarray(0, 4), bytes.subarray(4)]),
      stdout,
      stderr: new Collect(),
      env: {},
    });
    expect(stdout.text).toBe("José [REDACTED]");
  });

  it("writes a file, and only once it is complete", async () => {
    const input = await file("app.log", LOG);
    const output = join(dir, "app.safe.log");
    const result = await cli(["scrub", input, "-o", output, "--quiet"]);
    expect(result).toEqual({ code: 0, stdout: "", stderr: "" });
    expect(await readFile(output, "utf8")).toContain("login [REDACTED]");
    expect((await readdir(dir)).sort()).toEqual(["app.log", "app.safe.log"]);
  });

  it("applies presets, a strategy and a label", async () => {
    const text = "CPF 529.982.247-25, card 4111 1111 1111 1111\n";
    const pci = await cli(["scrub", "-q", "--preset", "pci-dss"], text);
    expect(pci.stdout).toContain("529.982.247-25");
    expect(pci.stdout).toMatch(/\*+1111/);
    const both = await cli(["scrub", "-q", "-p", "pci-dss,lgpd"], text);
    expect(both.stdout).not.toContain("529.982.247-25");
    const labelled = await cli(["scrub", "-q", "-p", "pci-dss", "--label", "<x>"], text);
    expect(labelled.stdout).toBe("CPF 529.982.247-25, card <x>\n");
    const masked = await cli(["scrub", "-q", "-c", "email", "-s", "mask"], "ana@example.com");
    expect(masked.stdout).toMatch(/^\*+$/);
    const redacted = await cli(["scrub", "-q", "-c", "email", "-s", "redact"], "ana@example.com");
    expect(redacted.stdout).toBe("[REDACTED]");
  });

  it("needs a pepper for the hash strategy", async () => {
    const without = await cli(["scrub", "-s", "hash"], "ana@example.com");
    expect(without.code).toBe(2);
    expect(without.stderr).toContain("ANONYMA_HASH_PEPPER");
    const peppered = await cli(["scrub", "-q", "-c", "email", "-s", "hash"], "ana@example.com", {
      ANONYMA_HASH_PEPPER: "pepper-0123456789",
    });
    expect(peppered.code).toBe(0);
    expect(peppered.stdout).toMatch(/^[0-9a-f]+$/);
  });

  it("uses a policy document", async () => {
    const policy = await file(
      "policy.json",
      JSON.stringify({
        version: 1,
        id: "support-desk",
        categories: { include: ["email"], exclude: [] },
        patterns: [{ source: "TICKET-\\d+", category: "ticket" }],
        rules: { email: { strategy: "redact", label: "<email>" } },
      }),
    );
    const result = await cli(["scrub", "-q", "--policy", policy], "ana@example.com TICKET-42");
    expect(result.stdout).toContain("<email>");
    expect(result.stdout).toContain("[REDACTED]");
    const forced = await cli(["scrub", "-q", "--policy", policy, "-s", "mask"], "ana@example.com");
    expect(forced.stdout).toMatch(/^\*+$/);
    const broken = await file("broken.json", "{");
    expect((await cli(["scrub", "--policy", broken], "x")).stderr).toContain("is not JSON");
    const invalid = await file("invalid.json", JSON.stringify({ version: 9 }));
    expect((await cli(["scrub", "--policy", invalid], "x")).code).toBe(2);
  });

  it("scrubs every string of JSON Lines and keeps numbers and blank lines", async () => {
    const input = await file(
      "events.jsonl",
      '{"id":12345678901234567890,"user":{"email":"ana@example.com"}}\r\n\n{"ok":true}\nnot json bob@example.org',
    );
    const result = await cli(["scrub", input]);
    expect(result.stdout).toBe(
      '{"id":12345678901234567890,"user":{"email":"[REDACTED]"}}\r\n\n{"ok":true}\nnot json [REDACTED]',
    );
    expect(result.stderr).toContain("line 4 is not JSON; it was scrubbed as text");
    expect(result.stderr).toContain("replaced 2 values");
  });

  it("scrubs CSV cells and keeps the header, quoting and line endings", async () => {
    const input = await file(
      "people.csv",
      'name,email,note\r\nAna,ana@example.com,"call (11) 91234-5678"\r\nBob,,"x, y"\r\n',
    );
    const result = await cli(["scrub", input, "-q"]);
    expect(result.stdout).toBe(
      'name,email,note\r\nAna,[REDACTED],"call [REDACTED]"\r\nBob,,"x, y"\r\n',
    );
  });

  it("scrubs only the columns asked for, by name or number", async () => {
    const csv = "\uFEFFEmail,Note\nana@example.com,bob@example.org\n";
    const byName = await cli(["scrub", "-q", "-f", "csv", "--columns", "email"], csv);
    expect(byName.stdout).toBe("\uFEFFEmail,Note\n[REDACTED],bob@example.org\n");
    const byNumber = await cli(["scrub", "-q", "-f", "csv", "--columns", "2"], csv);
    expect(byNumber.stdout).toBe("\uFEFFEmail,Note\nana@example.com,[REDACTED]\n");
    const unknown = await cli(["scrub", "-f", "csv", "--columns", "phone"], csv);
    expect(unknown.code).toBe(2);
    expect(unknown.stderr).toContain('No column "phone" in the header: Email, Note');
  });

  it("treats the first row as data with --no-header", async () => {
    const result = await cli(
      ["scrub", "-q", "-f", "csv", "--no-header", "--columns", "1"],
      "ana@example.com,bob@example.org\n",
    );
    expect(result.stdout).toBe("[REDACTED],bob@example.org\n");
    const noColumns = await cli(["scrub", "-f", "csv", "--no-header", "--columns", "x"], "a\n");
    expect(noColumns.stderr).toContain("column numbers");
    const missing = await cli(["scrub", "-f", "csv", "--no-header", "--columns", "0"], "a\n");
    expect(missing.stderr).toContain('No column "0" in the header.');
  });

  it("reads TSV with a tab delimiter", async () => {
    const input = await file("people.tsv", "name\temail\nAna\tana@example.com\n");
    expect((await cli(["scrub", input, "-q"])).stdout).toBe("name\temail\nAna\t[REDACTED]\n");
    const forced = await cli(
      ["scrub", "-q", "-f", "csv", "-d", "\\t"],
      "a\tb\nx\tana@example.com\n",
    );
    expect(forced.stdout).toBe("a\tb\nx\t[REDACTED]\n");
  });

  it("reads and writes gzip", async () => {
    const input = await file("app.log.gz", gzipSync(LOG));
    const output = join(dir, "safe.log.gz");
    expect((await cli(["scrub", input, "-o", output, "-q"])).code).toBe(0);
    expect(gunzipSync(await readFile(output)).toString("utf8")).toContain("login [REDACTED]");
  });

  it("writes a receipt that verifies against the output", async () => {
    const input = await file(
      "people.csv",
      "name,email\nAna,ana@example.com\nBob,bob@example.org\n",
    );
    const output = join(dir, "safe.csv");
    const receiptPath = join(dir, "receipt.json");
    const result = await cli(
      ["scrub", input, "-o", output, "--receipt", receiptPath, "-p", "lgpd"],
      "",
      { ANONYMA_RECEIPT_KEY: KEY },
    );
    expect(result.stderr).toContain(`receipt in ${receiptPath}`);
    const receipt: unknown = JSON.parse(await readFile(receiptPath, "utf8"));
    expect(receipt).toMatchObject({ presets: ["lgpd"], stats: { email: 2 }, total: 2 });
    const verified = await createReceiptIssuer({ key: KEY }).verify(receipt, {
      output: await readFile(output, "utf8"),
    });
    expect(verified.valid).toBe(true);

    const policy = await file("p.json", JSON.stringify({ version: 1, id: "desk" }));
    await cli(["scrub", input, "-q", "--policy", policy, "--receipt", receiptPath], "", {
      ANONYMA_RECEIPT_KEY: KEY,
    });
    expect(JSON.parse(await readFile(receiptPath, "utf8"))).toMatchObject({
      policy: { id: "desk" },
    });
  });

  it("needs a key for a receipt", async () => {
    const result = await cli(["scrub", "--receipt", join(dir, "r.json")], "x");
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("ANONYMA_RECEIPT_KEY");
  });

  it("leaves no output file behind when it fails", async () => {
    const output = join(dir, "out.csv");
    const result = await cli(["scrub", "-f", "csv", "-o", output, "--columns", "nope"], "a\n1\n");
    expect(result.code).toBe(2);
    expect(await readdir(dir)).toEqual([]);
  });

  it("reports an output it cannot write", async () => {
    const result = await cli(["scrub", "-o", join(dir, "missing", "out.txt")], "ana@example.com");
    expect(result.code).toBe(2);
    expect(result.stderr).toMatch(/^anonyma: /);
  });

  it("stops quietly when standard output is closed", async () => {
    const stdout = new Writable({
      write(_chunk, _encoding, done) {
        done(Object.assign(new Error("write EPIPE"), { code: "EPIPE" }));
      },
    });
    const stderr = new Collect();
    const code = await run(["scrub"], {
      stdin: Readable.from([Buffer.from("ana@example.com\n".repeat(10))]),
      stdout,
      stderr,
      env: {},
    });
    expect(code).toBe(0);
    expect(stderr.text).toBe("");
  });
});

describe("anonyma scan", () => {
  it("summarises what it finds without changing anything", async () => {
    const result = await cli(["scan"], LOG);
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/^<stdin>: 3 values in 2 of 3 lines\n/);
    expect(result.stdout).toMatch(/ {2}email +1\n/);
    expect(result.stdout).not.toContain("ana@example.com");
  });

  it("lists every finding with its line and column, and the summary on standard error", async () => {
    const input = await file("app.log", LOG);
    const result = await cli(["scan", input, "--list"]);
    expect(result.stdout.split("\n")).toContain(`${input}:1:14: email`);
    expect(result.stderr).toContain("3 values in 2 of 3 lines");
    const quiet = await cli(["scan", input, "--list", "-q"]);
    expect(quiet.stderr).toBe("");
  });

  it("prints a JSON summary", async () => {
    const result = await cli(["scan", "--json"], LOG);
    expect(JSON.parse(result.stdout)).toEqual({
      input: "<stdin>",
      format: "txt",
      lines: 3,
      linesWithPii: 2,
      total: 3,
      categories: { "credit-card": 1, email: 1, ipv4: 1 },
    });
  });

  it("says when nothing was found", async () => {
    expect((await cli(["scan"], "nothing here\n")).stdout).toBe(
      "<stdin>: no personal data found in 1 line\n",
    );
  });

  it("fails on personal data when asked to", async () => {
    expect((await cli(["scan", "--fail-on-pii"], LOG)).code).toBe(1);
    expect((await cli(["scan", "--fail-on-pii"], "clean\n")).code).toBe(0);
  });

  it("reports JSON Lines findings by JSON Pointer", async () => {
    const result = await cli(
      ["scan", "-f", "jsonl", "--list"],
      '{"to":["ana@example.com","bob@example.org"]}\n\n{"n":1}\nnot json ana@example.com\n',
    );
    expect(result.stdout).toContain("<stdin>:1: /to/0 email");
    expect(result.stdout).toContain("<stdin>:4: 10 email");
    expect(result.stderr).toContain("line 4 is not JSON; it was scanned as text");
    const grouped = await cli(
      ["scan", "-f", "jsonl", "--list", "-q"],
      '{"a":"ana@example.com bob@example.org"}\n',
    );
    expect(grouped.stdout).toBe("<stdin>:1: /a email (2)\n");
  });

  it("reports CSV findings by record and column", async () => {
    const result = await cli(
      ["scan", "-f", "csv", "--list", "-q"],
      'name,email,\nAna,ana@example.com,"multi\nline ana@example.com"\n',
    );
    expect(result.stdout).toBe("<stdin>:2: email email\n<stdin>:2: column 3 email\n");
    const json = await cli(["scan", "-f", "csv", "--json", "--no-header"], "ana@example.com\nx\n");
    expect(JSON.parse(json.stdout)).toMatchObject({ records: 2, recordsWithPii: 1, total: 1 });
    const columns = await cli(
      ["scan", "-f", "csv", "--columns", "name", "--json"],
      "name,email\nAna,ana@example.com\n",
    );
    expect(JSON.parse(columns.stdout)).toMatchObject({ total: 0 });
  });
});

describe("command line", () => {
  it("prints help and the version", async () => {
    expect((await cli(["--help"])).stdout).toContain("anonyma scrub");
    expect((await cli(["help"])).stdout).toContain("anonyma scan");
    expect((await cli(["-v"])).stdout).toMatch(
      new RegExp(`^anonyma-cli ${CLI_VERSION} \\(anonyma \\d`),
    );
  });

  it("reports a missing input file", async () => {
    const result = await cli(["scan", join(dir, "nope.txt")]);
    expect(result).toMatchObject({ code: 2, stderr: expect.stringContaining("no such file") });
  });

  it.each<[string[], string]>([
    [[], "Name a command"],
    [["frob"], 'Unknown command "frob"'],
    [["scan", "a", "b"], "Give one input"],
    [["scan", "--bogus"], "Unknown option"],
    [["scan", "-p", "nope"], 'Unknown preset "nope"'],
    [["scan", "-c", "nope"], 'Unknown category "nope"'],
    [["scrub", "-s", "encrypt"], 'Unknown strategy "encrypt"'],
    [["scan", "--min-confidence", "2"], "--min-confidence"],
    [["scan", "--min-confidence", "x"], "--min-confidence"],
    [["scan", "-f", "xml"], 'Unknown format "xml"'],
    [["scan", "-f", "csv", "-d", ";;"], "--delimiter"],
    [["scan", "--policy", "p.json", "-p", "gdpr"], "A policy names its own categories"],
    [["scan", "-o", "out.txt"], "--output applies to scrub"],
    [["scan", "-s", "mask"], "--strategy applies to scrub"],
    [["scrub", "--json"], "--json applies to scan"],
    [["scrub", "--fail-on-pii"], "--fail-on-pii applies to scan"],
    [["scrub", "-s", "mask", "--label", "x"], "--label applies to the redact strategy"],
    [["scan", "--columns", "a"], "--columns applies to CSV input"],
    [["scan", "-d", ";"], "--delimiter applies to CSV input"],
    [["scan", "--no-header"], "--no-header applies to CSV input"],
    [["scrub", "a.txt", "-o", "a.txt"], "must not be the input"],
    [["scan", "--json", "--list"], "--json and --list"],
  ])("rejects %j", async (args, message) => {
    const result = await cli(args);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain(message);
    expect(result.stderr).toContain('Run "anonyma --help" for usage.');
  });

  it("chooses the format from the file extension", () => {
    expect(formatOf("a.jsonl")).toBe("jsonl");
    expect(formatOf("a.NDJSON.gz")).toBe("jsonl");
    expect(formatOf("a.tsv")).toBe("csv");
    expect(formatOf("a.csv.gz")).toBe("csv");
    expect(formatOf("a.log")).toBeUndefined();
    expect(formatOf("-")).toBeUndefined();
    expect(formatOf(undefined)).toBeUndefined();
    expect(parseCommandLine(["scan", "x.csv"]).format).toBe("csv");
  });
});

describe("lines", () => {
  it("splits chunks into lines with their endings", async () => {
    async function* chunks(): AsyncGenerator<string> {
      yield "a\r";
      yield "\nb\n";
      yield "c";
    }
    const out = [];
    for await (const line of lines(chunks())) out.push(line);
    expect(out).toEqual([
      { text: "a", eol: "\r\n" },
      { text: "b", eol: "\n" },
      { text: "c", eol: "" },
    ]);
  });
});

describe("version", () => {
  it("matches package.json", async () => {
    const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as {
      version: string;
    };
    expect(CLI_VERSION).toBe(pkg.version);
  });
});
