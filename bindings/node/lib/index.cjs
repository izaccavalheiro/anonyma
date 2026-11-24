"use strict";
/**
 * anonyma-native: anonyma's detection and anonymization on its Rust core, in
 * the shapes anonyma returns. An engine is built once from options and reused;
 * batches scan short texts together and spread over every core.
 *
 * It runs what the core runs: built-in detectors, presets, rules and default
 * strategies. Options it cannot honour (custom detectors and patterns,
 * allowlists, plugins, consistent tokens, a global replacement) are refused,
 * never ignored: use anonyma for those.
 */
const native = require("./load.cjs");

/** Options of anonyma that the core does not run. */
const REFUSED = [
  "customDetectors",
  "customPatterns",
  "globalReplacement",
  "consistentTokens",
  "enabledCategories",
  "allowlist",
  "plugins",
];

/** The engine options the core reads. */
const ENGINE_OPTIONS = ["categories", "preset", "rules", "defaultStrategy", "aggressive", "strict"];

class NativeOptionsError extends TypeError {
  constructor(message) {
    super(`anonyma-native: ${message}`);
    this.name = "NativeOptionsError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

function check(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new NativeOptionsError("options must be an object");
  }
  for (const key of Object.keys(options)) {
    if (REFUSED.includes(key)) {
      throw new NativeOptionsError(
        `${key} is not supported by the Rust core; use anonyma for this option`,
      );
    }
    if (!ENGINE_OPTIONS.includes(key)) {
      throw new NativeOptionsError(`unknown option ${key}`);
    }
  }
}

/** The texts of a batch that are strings, and an error for each that is not. */
function split(texts) {
  if (!Array.isArray(texts)) throw new TypeError("anonyma-native: texts must be an array");
  const strings = [];
  const failed = new Map();
  texts.forEach((text, index) => {
    if (typeof text === "string") strings.push(text);
    else failed.set(index, new TypeError(`anonyma-native: entry ${String(index)} is not a string`));
  });
  return { strings, failed };
}

/** Each entry of a batch, in input order, from the results of its strings. */
function merge(texts, failed, results, entry) {
  let next = 0;
  return texts.map((_, index) => {
    const error = failed.get(index);
    return error === undefined ? entry(index, results[next++]) : { index, ok: false, error };
  });
}

function text(value) {
  if (typeof value !== "string") throw new TypeError("anonyma-native: text must be a string");
  return value;
}

/**
 * Build an engine from options: `preset` (a name or a list), `rules`,
 * `defaultStrategy`, `categories`, `aggressive`, `strict` (check digits of
 * national IDs). Throws a `NativeOptionsError` on an option the core does not
 * run, and an `Error` on one it refuses.
 */
function createEngine(options = {}) {
  check(options);
  // The core reads a list of presets; anonyma also takes one name.
  const spec =
    typeof options.preset === "string" ? { ...options, preset: [options.preset] } : options;
  const engine = new native.Engine(JSON.stringify(spec));
  let closed = false;
  const live = () => {
    if (closed) throw new Error("anonyma-native: the engine is closed");
    return engine;
  };
  return {
    detect(value) {
      return live().detect(text(value));
    },
    anonymize(value, { includeMatches = false } = {}) {
      return live().anonymize(text(value), includeMatches);
    },
    detectBatch(texts) {
      const { strings, failed } = split(texts);
      const results = live().detectBatch(strings);
      return merge(texts, failed, results, (index, value) => ({ index, ok: true, value }));
    },
    anonymizeBatch(texts, { includeMatches = false } = {}) {
      const { strings, failed } = split(texts);
      const results = live().anonymizeBatch(strings, includeMatches);
      return merge(texts, failed, results, (index, result) =>
        result.error == null
          ? { index, ok: true, value: result.value }
          : { index, ok: false, error: new Error(result.error) },
      );
    },
    close() {
      closed = true;
    },
  };
}

module.exports = {
  createEngine,
  NativeOptionsError,
  call: native.call,
  Vault: native.Vault,
  coreVersion: native.coreVersion,
};
