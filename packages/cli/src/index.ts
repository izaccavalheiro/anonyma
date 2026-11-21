/**
 * @module anonyma-cli
 * @description The `anonyma` command, and its parts for programs that run it
 * themselves: {@link run}, the streaming CSV reader and writer, and the
 * command-line parser.
 *
 * ```sh
 * anonyma scrub customers.csv -o customers.safe.csv --preset lgpd
 * anonyma scan app.log.gz --fail-on-pii
 * ```
 */

export { run } from "./run.js";
export type { CliIo } from "./run.js";
export { CsvReader, formatCsvRecord } from "./csv.js";
export type { CsvRecord } from "./csv.js";
export { STRATEGIES, USAGE, UsageError, formatOf, parseCommandLine } from "./args.js";
export type { CliOptions, CliStrategy, Format } from "./args.js";
export { CLI_VERSION } from "./version.js";
