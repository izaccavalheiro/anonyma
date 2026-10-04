/**
 * @module vault/session
 * @description A synchronous, in-memory tokenization provider for one
 * session — typically one LLM conversation or one request.
 *
 * Tokens are numbered per category in the order values are first seen
 * (`[EMAIL_0001]`, `[EMAIL_0002]`, …), so the first value in a document gets
 * the first number. Two values share a token only when they are identical,
 * and a number is never handed out twice, not even after its token was
 * forgotten and the session was continued from a snapshot.
 */

import { ValidationError } from "../errors.js";
import { PREFIX_SOURCE, prefixResolver } from "./tokens.js";
import type { RestoreResult, TokenContext, TokenizationProvider } from "./types.js";

/**
 * A serialisable copy of a session, for keeping a conversation's tokens
 * between requests. It contains original values: store it as you would store
 * the data itself.
 */
export interface SessionSnapshot {
  /** Snapshot format version. */
  readonly v: 1;
  /** Token shape of the session. */
  readonly format: "bracket" | "angle";
  /** The session tag, when the session has one. */
  readonly tag?: string;
  /** Every token with its original value and category, in creation order. */
  readonly entries: readonly (readonly [token: string, value: string, category: string])[];
  /**
   * The last number handed out per token prefix. It can be higher than the
   * numbers in `entries` when tokens were forgotten, and keeps a forgotten
   * number from being issued again for another value.
   */
  readonly counters?: readonly (readonly [prefix: string, last: number])[];
}

/**
 * Options accepted by {@link createSessionTokenizer}.
 */
export interface SessionTokenizerOptions {
  /** Token shape: `[EMAIL_0001]` (`"bracket"`, default) or `<EMAIL_1>` (`"angle"`). */
  readonly format?: "bracket" | "angle";
  /**
   * 2 to 12 letters or digits inserted into every token (`[EMAIL_k3Xf_0001]`).
   * With an unpredictable tag, text that merely looks like a token — in the
   * input, or invented by a model — is never mistaken for one.
   */
  readonly tag?: string;
  /** Token prefixes for categories, overriding the defaults. */
  readonly prefixes?: Readonly<Record<string, string>>;
  /**
   * Maps a value to the key used to decide whether two values are the same.
   * Defaults to the value itself, so values are compared exactly.
   */
  readonly normalize?: (value: string, category: string) => string;
  /**
   * When `true`, {@link SessionTokenizer.restore} also accepts tokens whose
   * case, brackets, zero padding or inner spacing a language model changed.
   * Defaults to `false`.
   */
  readonly lenient?: boolean;
  /** Continue a previous session. */
  readonly snapshot?: SessionSnapshot;
}

/**
 * A {@link TokenizationProvider} whose operations are synchronous.
 */
export interface SessionTokenizer extends TokenizationProvider {
  readonly tokenize: (value: string, context: TokenContext) => string;
  readonly detokenize: (token: string) => string | undefined;
  /** Replace every token of this session found in `text` with its original value. */
  readonly restore: (text: string) => RestoreResult;
  /** Remove one token from the session. Returns `true` when it existed. */
  readonly forget: (token: string) => boolean;
  /** Number of tokens in the session. */
  readonly size: () => number;
  /** A serialisable copy of the session. */
  readonly snapshot: () => SessionSnapshot;
}

const TAG_PATTERN = /^[A-Za-z0-9]{2,12}$/;
const FORMATS: ReadonlySet<string> = new Set(["bracket", "angle"]);

/**
 * Create a session tokenizer.
 *
 * @param options - Token shape, optional tag, and optionally a snapshot to continue from.
 * @returns The {@link SessionTokenizer}.
 * @throws {@link ValidationError} When an option or the snapshot is invalid.
 *
 * @example
 * ```ts
 * import { compilePipeline } from "anonyma/engine";
 * import { createSessionTokenizer } from "anonyma/vault";
 *
 * const session = createSessionTokenizer();
 * const pipeline = compilePipeline({ defaultStrategy: { strategy: "tokenize" } }, { tokenization: session });
 *
 * const prompt = pipeline.transform("Mail alice@example.com, cc bob@example.com").text;
 * // "Mail [EMAIL_0001], cc [EMAIL_0002]"
 * session.restore("Sent to [EMAIL_0002].").text;
 * // "Sent to bob@example.com."
 * ```
 */
export function createSessionTokenizer(options: SessionTokenizerOptions = {}): SessionTokenizer {
  const format = options.snapshot?.format ?? options.format ?? "bracket";
  const tag = options.snapshot?.tag ?? options.tag;
  const { lenient = false } = options;
  const normalize = options.normalize ?? ((value: string): string => value);

  if (!FORMATS.has(format)) {
    throw new ValidationError("format", 'must be "bracket" or "angle"');
  }
  if (tag !== undefined && !TAG_PATTERN.test(tag)) {
    throw new ValidationError("tag", "must be 2-12 letters or digits");
  }

  const prefixOf = prefixResolver(options.prefixes);
  const [open, close] = format === "bracket" ? ["[", "]"] : ["<", ">"];
  const infix = tag === undefined ? "" : `${tag}_`;
  const escapedOpen = format === "bracket" ? "\\[" : "<";
  const escapedClose = format === "bracket" ? "\\]" : ">";
  const body = `(${PREFIX_SOURCE})_${infix}(\\d+)`;

  const tokenPattern = new RegExp(`${escapedOpen}${body}${escapedClose}`, "g");
  // What a language model may turn a token into: other brackets, escapes, spaces, case, padding.
  // Every part is bounded, so text that only looks like the start of a token costs a fixed amount.
  const lenientPattern = new RegExp(
    String.raw`\\?[\[<(\uff3b]\s{0,4}([A-Za-z][A-Za-z0-9]{0,39}(?:\\?_[A-Za-z0-9]{1,40}){0,12}?)\\?_(\d{1,12})\s{0,4}\\?[\]>)\uff3d]`,
    "g",
  );
  const partialTokenPattern = lenient
    ? /\\?[[<(\uff3b][A-Za-z0-9_\\ \t]{0,90}$|\\$/
    : new RegExp(`${escapedOpen}[A-Za-z0-9_]{0,60}$`);

  /** token -> original value */
  const values = new Map<string, string>();
  /** token -> category */
  const categories = new Map<string, string>();
  /** prefix NUL normalised value -> token */
  const index = new Map<string, string>();
  /** prefix -> last number handed out */
  const counters = new Map<string, number>();
  /** canonical key (see `canonical`) -> token, for lenient restoration */
  const canonicalIndex = new Map<string, string>();
  /** token -> the keys it occupies in `index` and `canonicalIndex` */
  const registrations = new Map<
    string,
    { readonly indexKey: string; readonly canonicalKey: string }
  >();

  function canonical(prefix: string, number: string): string {
    return `${prefix.toUpperCase()}#${String(Number(number))}`;
  }

  function register(token: string, value: string, category: string): void {
    const parsed = new RegExp(`^${escapedOpen}${body}${escapedClose}$`).exec(token);
    const prefix = parsed?.[1];
    const number = parsed?.[2];
    if (prefix === undefined || number === undefined) {
      throw new ValidationError(
        "snapshot",
        "contains a token that does not belong to this session",
      );
    }
    const indexKey = `${prefix}\0${normalize(value, category)}`;
    const canonicalKey = canonical(prefix, number);
    values.set(token, value);
    categories.set(token, category);
    index.set(indexKey, token);
    counters.set(prefix, Math.max(counters.get(prefix) ?? 0, Number(number)));
    canonicalIndex.set(canonicalKey, token);
    registrations.set(token, { indexKey, canonicalKey });
  }

  if (options.snapshot !== undefined) {
    const candidate: { readonly v?: unknown; readonly entries?: unknown } = options.snapshot;
    if (candidate.v !== 1 || !Array.isArray(candidate.entries)) {
      throw new ValidationError("snapshot", "is not a version 1 session snapshot");
    }
    for (const entry of candidate.entries as readonly unknown[]) {
      const [token, value, category] = Array.isArray(entry) ? (entry as readonly unknown[]) : [];
      if (typeof token !== "string" || typeof value !== "string" || typeof category !== "string") {
        throw new ValidationError("snapshot", "contains a malformed entry");
      }
      register(token, value, category);
    }
    const saved: unknown = (candidate as { readonly counters?: unknown }).counters;
    if (saved !== undefined) {
      if (!Array.isArray(saved)) {
        throw new ValidationError("snapshot", "contains malformed counters");
      }
      for (const entry of saved as readonly unknown[]) {
        const [prefix, last] = Array.isArray(entry) ? (entry as readonly unknown[]) : [];
        if (typeof prefix !== "string" || typeof last !== "number" || !Number.isSafeInteger(last)) {
          throw new ValidationError("snapshot", "contains malformed counters");
        }
        counters.set(prefix, Math.max(counters.get(prefix) ?? 0, last));
      }
    }
  }

  function tokenize(value: string, context: TokenContext): string {
    if (typeof value !== "string") throw new ValidationError("value", "must be a string");
    const prefix = prefixOf(context.category);
    const key = `${prefix}\0${normalize(value, context.category)}`;
    const existing = index.get(key);
    if (existing !== undefined) return existing;

    const number = (counters.get(prefix) ?? 0) + 1;
    const digits = format === "bracket" ? String(number).padStart(4, "0") : String(number);
    const token = `${open}${prefix}_${infix}${digits}${close}`;
    register(token, value, context.category);
    return token;
  }

  function detokenize(token: string): string | undefined {
    return values.get(token);
  }

  function resolveLenient(prefix: string, number: string): string | undefined {
    let cleaned = prefix.replace(/\\/g, "");
    if (tag !== undefined) {
      const suffix = `_${tag}`;
      if (!cleaned.toLowerCase().endsWith(suffix.toLowerCase())) return undefined;
      cleaned = cleaned.slice(0, -suffix.length);
    }
    const token = canonicalIndex.get(canonical(cleaned, number));
    return token === undefined ? undefined : values.get(token);
  }

  function restore(text: string): RestoreResult {
    if (typeof text !== "string") throw new ValidationError("text", "must be a string");
    let restored = 0;
    const unresolved: string[] = [];
    const pattern = lenient ? lenientPattern : tokenPattern;
    pattern.lastIndex = 0;
    const out = text.replace(pattern, (token: string, prefix: string, number: string) => {
      const value = lenient
        ? (values.get(token) ?? resolveLenient(prefix, number))
        : values.get(token);
      if (value === undefined) {
        unresolved.push(token);
        return token;
      }
      restored++;
      return value;
    });
    return { text: out, restored, unresolved };
  }

  function forget(token: string): boolean {
    const registration = registrations.get(token);
    if (registration === undefined) return false;
    values.delete(token);
    categories.delete(token);
    registrations.delete(token);
    // Only release the keys if they still point at this token.
    if (index.get(registration.indexKey) === token) index.delete(registration.indexKey);
    if (canonicalIndex.get(registration.canonicalKey) === token) {
      canonicalIndex.delete(registration.canonicalKey);
    }
    return true;
  }

  function snapshot(): SessionSnapshot {
    return {
      v: 1,
      format,
      ...(tag !== undefined ? { tag } : {}),
      entries: [...values].map(
        ([token, value]) => [token, value, categories.get(token) ?? ""] as const,
      ),
      counters: [...counters],
    };
  }

  return Object.freeze({
    scheme: "session",
    reversible: true,
    tokenPattern,
    partialTokenPattern,
    // Escapes and spaces a model may add make a lenient token longer.
    maxTokenLength: lenient ? 96 : 64,
    tokenize,
    detokenize,
    restore,
    forget,
    size: (): number => values.size,
    snapshot,
  });
}
