/** A value found: the `PiiMatch` of anonyma, offsets in UTF-16 code units. */
export interface PiiMatch {
  readonly category: string;
  readonly value: string;
  readonly start: number;
  readonly end: number;
  readonly confidence: number;
}

/** An anonymized text: the `AnonymizeResult` of anonyma. */
export interface AnonymizeResult {
  readonly text: string;
  /** The values replaced; empty unless `includeMatches` is set. */
  readonly matches: readonly PiiMatch[];
}

/** One entry of a batch, as anonyma's batch functions return it. */
export type BatchResult<T> =
  | { readonly index: number; readonly ok: true; readonly value: T }
  | { readonly index: number; readonly ok: false; readonly error: Error };

/** A strategy, as anonyma writes it: `{ strategy: "mask", ... }`. */
export interface StrategyOptions {
  readonly strategy: string;
  readonly [option: string]: unknown;
}

/** The options the Rust core runs; others are refused with a `NativeOptionsError`. */
export interface EngineOptions {
  /** A preset name, or several (combined as anonyma combines them). */
  readonly preset?: string | readonly string[];
  readonly rules?: readonly { readonly category: string; readonly strategy: StrategyOptions }[];
  readonly defaultStrategy?: StrategyOptions;
  readonly categories?: readonly string[];
  readonly aggressive?: boolean;
  /** Verify the check digits of national IDs. */
  readonly strict?: boolean;
}

/** An engine built once; see {@link createEngine}. */
export interface Engine {
  detect(text: string): PiiMatch[];
  anonymize(text: string, options?: { readonly includeMatches?: boolean }): AnonymizeResult;
  /** One entry per text, in order; short texts are scanned together, on every core. */
  detectBatch(texts: readonly string[]): BatchResult<PiiMatch[]>[];
  anonymizeBatch(
    texts: readonly string[],
    options?: { readonly includeMatches?: boolean },
  ): BatchResult<AnonymizeResult>[];
  /** Later calls throw. */
  close(): void;
}

/** Build an engine from options; throws on an option the core does not run. */
export function createEngine(options?: EngineOptions): Engine;

/** Thrown for an option of anonyma that the Rust core does not run. */
export class NativeOptionsError extends TypeError {}

/** The JSON API of the core: `{"ok": ...}` or `{"error": ...}`. */
export function call(op: string, inputJson: string): string;

/** The version of the Rust core. */
export function coreVersion(): string;

/** A token vault for the JSON API's `shield` and `restore`. */
export class Vault {
  constructor();
  call(op: string, inputJson: string): string;
  readonly size: number;
}
