/**
 * @module anonyma-cli/run
 * @description The command: parse the arguments, build the pipeline, run
 * `scrub` or `scan`, and report.
 */

import { readFile, writeFile } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";
import { VERSION as ANONYMA_VERSION, combinePresets } from "anonyma";
import type { PiiCategory } from "anonyma";
import { createReceiptIssuer } from "anonyma/audit";
import type { AuditPolicyRef } from "anonyma/audit";
import { parsePolicy, policyToSpec } from "anonyma/compliance";
import { compilePipeline } from "anonyma/engine";
import type { CompileDependencies, Pipeline, PipelineSpec, StrategySpec } from "anonyma/engine";
import { USAGE, UsageError, parseCommandLine } from "./args.js";
import type { CliOptions } from "./args.js";
import { scan, scrub } from "./commands.js";
import type { Finding, Totals } from "./commands.js";
import { openInput, openOutput } from "./io.js";
import { CLI_VERSION } from "./version.js";

/** The streams and environment of a run. */
export interface CliIo {
  readonly stdin: Readable;
  readonly stdout: Writable;
  readonly stderr: Writable;
  readonly env: Readonly<Record<string, string | undefined>>;
}

const RECEIPT_KEY = "ANONYMA_RECEIPT_KEY";
const HASH_PEPPER = "ANONYMA_HASH_PEPPER";

function strategySpec(options: CliOptions): StrategySpec | undefined {
  switch (options.strategy) {
    case undefined:
      return options.label === undefined ? undefined : { strategy: "redact", label: options.label };
    case "redact":
      return options.label === undefined
        ? { strategy: "redact" }
        : { strategy: "redact", label: options.label };
    default:
      return { strategy: options.strategy };
  }
}

/** The pipeline spec, its dependencies and what a receipt says about the policy. */
async function pipelineFor(
  options: CliOptions,
  env: CliIo["env"],
): Promise<{ pipeline: Pipeline; policy: AuditPolicyRef | undefined }> {
  let spec: PipelineSpec;
  let policy: AuditPolicyRef | undefined;
  const strategy = strategySpec(options);
  if (options.policy !== undefined) {
    const text = await readFile(options.policy, "utf8");
    let document: unknown;
    try {
      document = JSON.parse(text);
    } catch {
      throw new UsageError(`The policy ${options.policy} is not JSON.`);
    }
    const parsed = parsePolicy(document);
    policy = { id: parsed.id };
    spec = policyToSpec(parsed);
    if (strategy !== undefined) spec = { ...spec, defaultStrategy: strategy, rules: {} };
  } else if (strategy !== undefined) {
    // An explicit strategy applies to every category, so it replaces the presets' rules.
    // parseCommandLine() accepts built-in categories only.
    const categories =
      (options.categories as readonly PiiCategory[] | undefined) ??
      (options.presets.length > 0 ? combinePresets(options.presets).categories : undefined);
    spec = { ...(categories !== undefined ? { categories } : {}), defaultStrategy: strategy };
  } else {
    spec = {
      ...(options.presets.length > 0 ? { preset: options.presets } : {}),
      ...(options.categories !== undefined
        ? { categories: options.categories as readonly PiiCategory[] }
        : {}),
    };
  }
  spec = {
    ...spec,
    ...(options.minConfidence !== undefined ? { minConfidence: options.minConfidence } : {}),
    ...(options.detection !== undefined ? { detection: options.detection } : {}),
    ...(options.aggressive ? { aggressive: true } : {}),
  };

  const pepper = env[HASH_PEPPER];
  const usesHash =
    spec.defaultStrategy?.strategy === "hash" ||
    Object.values(spec.rules ?? {}).some((rule) => rule.strategy === "hash");
  if (usesHash && (pepper === undefined || pepper === "")) {
    throw new UsageError(
      `The hash strategy needs a pepper in ${HASH_PEPPER}: without one, a hash of a short value can be reversed by trying every value.`,
    );
  }
  const dependencies: CompileDependencies =
    pepper !== undefined && pepper !== "" ? { secrets: { hashPepper: pepper } } : {};
  return { pipeline: compilePipeline(spec, dependencies), policy };
}

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString("en-US")} ${count === 1 ? one : many}`;
}

function sortedTally(totals: Totals): [string, number][] {
  return [...totals.tally]
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
}

function totalOf(totals: Totals): number {
  return sortedTally(totals).reduce((sum, [, count]) => sum + count, 0);
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

/**
 * Run the command.
 *
 * @param argv - The arguments after the program name.
 * @param io - Standard streams and environment.
 * @returns The exit status: 0 success, 1 personal data found by `scan --fail-on-pii`, 2 error.
 *
 * @example
 * ```ts
 * import { run } from "anonyma-cli";
 *
 * process.exitCode = await run(["scrub", "in.csv", "-o", "out.csv", "--preset", "lgpd"], {
 *   stdin: process.stdin, stdout: process.stdout, stderr: process.stderr, env: process.env,
 * });
 * ```
 */
export async function run(argv: readonly string[], io: CliIo): Promise<number> {
  let options: CliOptions;
  try {
    options = parseCommandLine(argv);
  } catch (error) {
    write(io.stderr, `anonyma: ${(error as Error).message}\nRun "anonyma --help" for usage.\n`);
    return 2;
  }
  if (options.command === "help") {
    write(io.stdout, `${USAGE}\n`);
    return 0;
  }
  if (options.command === "version") {
    write(io.stdout, `anonyma-cli ${CLI_VERSION} (anonyma ${ANONYMA_VERSION})\n`);
    return 0;
  }

  const name = options.input === undefined || options.input === "-" ? "<stdin>" : options.input;
  const warn = (message: string): void => {
    if (!options.quiet) write(io.stderr, `anonyma: ${name}: ${message}\n`);
  };
  const sink = options.command === "scrub" ? openOutput(options.output, io.stdout) : undefined;

  try {
    const receiptKey = io.env[RECEIPT_KEY];
    if (options.receipt !== undefined && (receiptKey === undefined || receiptKey === "")) {
      throw new UsageError(`--receipt needs the signing key in ${RECEIPT_KEY}.`);
    }
    const { pipeline, policy } = await pipelineFor(options, io.env);
    const input = openInput(options.input, io.stdin);
    const context = { options, pipeline, warn };

    if (sink !== undefined) {
      const totals = await scrub(input, sink, context);
      await sink.close();
      const counts = Object.fromEntries(sortedTally(totals));
      if (options.receipt !== undefined && receiptKey !== undefined) {
        const issuer = createReceiptIssuer({
          key: receiptKey,
          ...(options.presets.length > 0 ? { presets: options.presets } : {}),
          ...(policy !== undefined ? { policy } : {}),
        });
        const receipt = await issuer.issue({ outputDigest: sink.digest(), counts });
        await writeFile(options.receipt, `${JSON.stringify(receipt, null, 2)}\n`);
      }
      if (!options.quiet) {
        const total = totalOf(totals);
        const detail = sortedTally(totals)
          .map(([category, count]) => `${category} ${String(count)}`)
          .join(", ");
        write(
          io.stderr,
          `anonyma: ${name}: replaced ${plural(total, "value")}${detail === "" ? "" : ` (${detail})`}` +
            `${options.receipt === undefined ? "" : `; receipt in ${options.receipt}`}\n`,
        );
      }
      return 0;
    }

    const report = options.list ? io.stdout : undefined;
    const totals = await scan(input, context, (finding: Finding) => {
      if (report === undefined) return;
      const count = finding.count > 1 ? ` (${String(finding.count)})` : "";
      const where =
        options.format === "txt"
          ? `${String(finding.line)}:${finding.where}:`
          : `${String(finding.line)}: ${finding.where}`;
      write(report, `${name}:${where} ${finding.category}${count}\n`);
    });
    const total = totalOf(totals);
    const unit = options.format === "csv" ? "record" : "line";
    if (options.json) {
      const summary = {
        input: name,
        format: options.format,
        [`${unit}s`]: totals.records,
        [`${unit}sWithPii`]: totals.recordsWithPii,
        total,
        categories: Object.fromEntries(sortedTally(totals)),
      };
      write(io.stdout, `${JSON.stringify(summary, null, 2)}\n`);
    } else if (!options.quiet || !options.list) {
      const out = options.list ? io.stderr : io.stdout;
      const rows = sortedTally(totals);
      const width = Math.max(0, ...rows.map(([category]) => category.length));
      const head =
        total === 0
          ? `${name}: no personal data found in ${plural(totals.records, unit)}`
          : `${name}: ${plural(total, "value")} in ${String(totals.recordsWithPii)} of ${plural(totals.records, unit)}`;
      write(
        out,
        `${[head, ...rows.map(([category, count]) => `  ${category.padEnd(width)}  ${String(count).padStart(6)}`)].join("\n")}\n`,
      );
    }
    return options.failOnPii && total > 0 ? 1 : 0;
  } catch (error) {
    await sink?.abort();
    const code = (error as { code?: unknown }).code;
    if (code === "EPIPE") return 0;
    const message =
      code === "ENOENT"
        ? `cannot open ${String((error as { path?: unknown }).path)}: no such file`
        : (error as Error).message;
    write(
      io.stderr,
      `anonyma: ${message}${error instanceof UsageError ? '\nRun "anonyma --help" for usage.' : ""}\n`,
    );
    return 2;
  }
}
