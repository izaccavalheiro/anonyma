/**
 * @module anonyma-cli/args
 * @description The command line: commands, options and their validation.
 * Parsed with `node:util` so that the command has no dependency but anonyma.
 */

import { extname } from "node:path";
import { parseArgs } from "node:util";
import { PRESET_REGISTRY } from "anonyma";
import type { CompliancePreset } from "anonyma";
import { BUILTIN_CATEGORIES } from "anonyma/engine";

/** A file format the command reads and writes. */
export type Format = "txt" | "jsonl" | "csv";

/** The strategies the command can apply without a key or a vault. */
export const STRATEGIES = [
  "redact",
  "mask",
  "pseudonymize",
  "synthesize",
  "generalize",
  "hash",
] as const;

/** A strategy the command can apply. */
export type CliStrategy = (typeof STRATEGIES)[number];

/** What the command was asked to do. */
export interface CliOptions {
  readonly command: "scrub" | "scan" | "help" | "version";
  /** Input file; `undefined` or `-` for standard input. */
  readonly input: string | undefined;
  /** Output file; `undefined` or `-` for standard output. */
  readonly output: string | undefined;
  readonly format: Format;
  readonly presets: readonly CompliancePreset[];
  readonly categories: readonly string[] | undefined;
  readonly strategy: CliStrategy | undefined;
  readonly label: string | undefined;
  readonly minConfidence: number | undefined;
  readonly detection: "precise" | "legacy" | undefined;
  readonly aggressive: boolean;
  readonly policy: string | undefined;
  readonly columns: readonly string[] | undefined;
  readonly header: boolean;
  readonly delimiter: string;
  readonly receipt: string | undefined;
  readonly json: boolean;
  readonly list: boolean;
  readonly failOnPii: boolean;
  readonly quiet: boolean;
}

/** A mistake on the command line. The message says what to change. */
export class UsageError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export const USAGE = `Usage:
  anonyma scrub [input] [-o output] [options]   Replace personal data and write the result
  anonyma scan  [input] [options]               Report personal data without changing anything

The input is a file, or standard input when it is "-" or left out. The output
is a file, or standard output. Files ending in .gz are read or written
compressed. Nothing leaves the machine.

Formats (-f), chosen from the file extension when not given:
  txt     Plain text, such as logs (default)
  jsonl   JSON Lines: every string of every line, structure and numbers kept
  csv     CSV (.csv) or TSV (.tsv); the header row names the columns

Detection:
  -p, --preset <list>        Compliance presets, comma-separated: ${Object.keys(PRESET_REGISTRY).join(", ")}
  -c, --categories <list>    Categories to detect (default: those of the presets, or all)
      --policy <file>        A policy document (JSON) from anonyma/compliance
      --min-confidence <n>   Leave detections below this confidence, 0 to 1
      --aggressive           Also use the permissive detector variants
      --legacy               Use the 1.x detectors instead of the validating ones

Replacement (scrub):
  -s, --strategy <name>      ${STRATEGIES.join(", ")} (default: the presets' strategies, or redact)
      --label <text>         Replacement text of the redact strategy (default: [REDACTED])
      --receipt <file>       Write a signed receipt of the run; the key is read from
                             the ANONYMA_RECEIPT_KEY environment variable
  The hash strategy reads its pepper from ANONYMA_HASH_PEPPER.

CSV:
      --columns <list>       Only these columns, by header name or 1-based number
      --no-header            The first row is data
  -d, --delimiter <char>     Field delimiter (default: "," or a tab for .tsv)

Report (scan):
      --json                 Print the summary as JSON
      --list                 Print every finding as file:line:column: category
      --fail-on-pii          Exit with status 1 when personal data is found

  -o, --output <file>        Where scrub writes (default: standard output)
  -f, --format <format>      txt, jsonl or csv
  -q, --quiet                Print no summary on standard error
  -h, --help                 Show this help
  -v, --version              Show the version

Exit status: 0 success, 1 personal data found (scan --fail-on-pii), 2 error.`;

function list(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item !== "");
}

/** The format of `path`, from its extension; `.gz` is looked through. */
export function formatOf(path: string | undefined): Format | undefined {
  if (path === undefined || path === "-") return undefined;
  const extension = extname(path.replace(/\.gz$/i, "")).toLowerCase();
  if (extension === ".jsonl" || extension === ".ndjson") return "jsonl";
  if (extension === ".csv" || extension === ".tsv") return "csv";
  return undefined;
}

/**
 * Parse the command line.
 *
 * @param argv - The arguments after the program name.
 * @returns The options.
 * @throws {@link UsageError} When an argument is unknown or invalid.
 */
export function parseCommandLine(argv: readonly string[]): CliOptions {
  let parsed: ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>;
  try {
    parsed = parseArgs({ args: [...argv], options: OPTIONS, allowPositionals: true, strict: true });
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
  const { values, positionals } = parsed;
  const [first, ...rest] = positionals;

  if (values.help === true || first === "help") return defaults("help");
  if (values.version === true) return defaults("version");
  if (first === undefined) throw new UsageError("Name a command: scrub or scan.");
  if (first !== "scrub" && first !== "scan") {
    throw new UsageError(`Unknown command "${first}". The commands are scrub and scan.`);
  }
  if (rest.length > 1) throw new UsageError(`Give one input, not ${String(rest.length)}.`);
  const input = rest[0];

  const presets = list(values.preset) ?? [];
  for (const preset of presets) {
    if (!Object.hasOwn(PRESET_REGISTRY, preset)) {
      throw new UsageError(
        `Unknown preset "${preset}". The presets are ${Object.keys(PRESET_REGISTRY).join(", ")}.`,
      );
    }
  }
  const categories = list(values.categories);
  for (const category of categories ?? []) {
    if (!(BUILTIN_CATEGORIES as readonly string[]).includes(category)) {
      throw new UsageError(
        `Unknown category "${category}". The categories are ${BUILTIN_CATEGORIES.join(", ")}.`,
      );
    }
  }
  const strategy = values.strategy;
  if (strategy !== undefined && !(STRATEGIES as readonly string[]).includes(strategy)) {
    throw new UsageError(
      `Unknown strategy "${strategy}". The strategies are ${STRATEGIES.join(", ")}.`,
    );
  }
  let minConfidence: number | undefined;
  if (values["min-confidence"] !== undefined) {
    minConfidence = Number(values["min-confidence"]);
    if (!(minConfidence >= 0 && minConfidence <= 1)) {
      throw new UsageError("--min-confidence must be a number between 0 and 1.");
    }
  }
  const named = values.format;
  if (named !== undefined && named !== "txt" && named !== "jsonl" && named !== "csv") {
    throw new UsageError(`Unknown format "${named}". The formats are txt, jsonl and csv.`);
  }
  const format: Format = named ?? formatOf(input) ?? "txt";
  const tsv = input !== undefined && /\.tsv(?:\.gz)?$/i.test(input);
  const delimiter = values.delimiter === "\\t" ? "\t" : (values.delimiter ?? (tsv ? "\t" : ","));
  if (delimiter.length !== 1 || delimiter === '"' || delimiter === "\n" || delimiter === "\r") {
    throw new UsageError("--delimiter must be one character other than a quote or a line break.");
  }
  if (values.policy !== undefined && (presets.length > 0 || categories !== undefined)) {
    throw new UsageError("A policy names its own categories: leave out --preset and --categories.");
  }

  const command = first;
  if (command === "scan") {
    for (const option of ["output", "strategy", "label", "receipt"] as const) {
      if (values[option] !== undefined) {
        throw new UsageError(`--${option} applies to scrub, not to scan.`);
      }
    }
  } else {
    for (const option of ["json", "list", "fail-on-pii"] as const) {
      if (values[option] === true)
        throw new UsageError(`--${option} applies to scan, not to scrub.`);
    }
  }
  if (values.json === true && values.list === true) {
    throw new UsageError(
      "--json and --list cannot be combined: --list prints one line per finding.",
    );
  }
  if (values.label !== undefined && (strategy ?? "redact") !== "redact") {
    throw new UsageError("--label applies to the redact strategy.");
  }
  if (format !== "csv") {
    for (const option of ["columns", "delimiter"] as const) {
      if (values[option] !== undefined) throw new UsageError(`--${option} applies to CSV input.`);
    }
    if (values["no-header"] === true) throw new UsageError("--no-header applies to CSV input.");
  }
  const columns = list(values.columns);
  if (
    columns !== undefined &&
    values["no-header"] === true &&
    columns.some((c) => !/^\d+$/.test(c))
  ) {
    throw new UsageError("Without a header, --columns takes column numbers.");
  }
  if (
    values.output !== undefined &&
    values.output !== "-" &&
    input !== undefined &&
    values.output === input
  ) {
    throw new UsageError("The output must not be the input file.");
  }

  return {
    command,
    input,
    output: values.output,
    format,
    presets: presets as CompliancePreset[],
    categories,
    strategy: strategy as CliStrategy | undefined,
    label: values.label,
    minConfidence,
    detection: values.legacy === true ? "legacy" : undefined,
    aggressive: values.aggressive === true,
    policy: values.policy,
    columns,
    header: values["no-header"] !== true,
    delimiter,
    receipt: values.receipt,
    json: values.json === true,
    list: values.list === true,
    failOnPii: values["fail-on-pii"] === true,
    quiet: values.quiet === true,
  };
}

const OPTIONS = {
  output: { type: "string", short: "o" },
  format: { type: "string", short: "f" },
  preset: { type: "string", short: "p" },
  categories: { type: "string", short: "c" },
  policy: { type: "string" },
  "min-confidence": { type: "string" },
  aggressive: { type: "boolean" },
  legacy: { type: "boolean" },
  strategy: { type: "string", short: "s" },
  label: { type: "string" },
  receipt: { type: "string" },
  columns: { type: "string" },
  "no-header": { type: "boolean" },
  delimiter: { type: "string", short: "d" },
  json: { type: "boolean" },
  list: { type: "boolean" },
  "fail-on-pii": { type: "boolean" },
  quiet: { type: "boolean", short: "q" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
} as const;

function defaults(command: "help" | "version"): CliOptions {
  return {
    command,
    input: undefined,
    output: undefined,
    format: "txt",
    presets: [],
    categories: undefined,
    strategy: undefined,
    label: undefined,
    minConfidence: undefined,
    detection: undefined,
    aggressive: false,
    policy: undefined,
    columns: undefined,
    header: true,
    delimiter: ",",
    receipt: undefined,
    json: false,
    list: false,
    failOnPii: false,
    quiet: false,
  };
}
