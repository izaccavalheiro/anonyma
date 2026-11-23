/**
 * @module anonyma-conformance/typescript
 * @description The adapter of the TypeScript reference implementation: every
 * operation of the suite through the public API of `anonyma`.
 */

import {
  InMemoryVault,
  anonymize,
  combinePresets,
  detect,
  detokenize,
  restore,
  tokenize,
} from "anonyma";
import type { AnonymizationRule, CompliancePreset, PiiCategory } from "anonyma";
import { canonicalize, createReceiptIssuer, hmacSha256Hex, sha256Hex } from "anonyma/audit";
import { detectNationalIdStrict } from "anonyma/detectors";
import { CHECKSUMS } from "anonyma/validators";
import type { ChecksumName } from "anonyma/validators";

import { utf16ToCodePoints } from "./index.js";
import type { Adapter, ConformanceCase, JsonObject } from "./index.js";

/** Domain separator of receipt signatures (specification, "receipt.sign"). */
export const RECEIPT_DOMAIN = "anonyma/receipt/v1\0";

function fail(testCase: ConformanceCase, member: string, wanted: string): never {
  throw new TypeError(`${testCase.id}: input.${member} must be ${wanted}`);
}

function text(testCase: ConformanceCase, member: string): string {
  const value = testCase.input[member];
  return typeof value === "string" ? value : fail(testCase, member, "a string");
}

function strings(testCase: ConformanceCase, member: string): string[] {
  const value = testCase.input[member];
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? value
    : fail(testCase, member, "a list of strings");
}

function flag(testCase: ConformanceCase, member: string): boolean {
  const value = testCase.input[member];
  return value === undefined
    ? false
    : typeof value === "boolean"
      ? value
      : fail(testCase, member, "a boolean");
}

function pairs(testCase: ConformanceCase, member: string): [string, string][] {
  const value = testCase.input[member];
  const valid =
    Array.isArray(value) &&
    value.every(
      (item) =>
        Array.isArray(item) &&
        item.length === 2 &&
        typeof item[0] === "string" &&
        typeof item[1] === "string",
    );
  return valid ? (value as [string, string][]) : fail(testCase, member, "a list of string pairs");
}

function object(testCase: ConformanceCase, member: string): JsonObject {
  const value = testCase.input[member];
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : fail(testCase, member, "an object");
}

async function hmacKey(key: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

function isChecksumName(name: string): name is ChecksumName {
  return Object.hasOwn(CHECKSUMS, name);
}

async function run(testCase: ConformanceCase): Promise<unknown> {
  switch (testCase.op) {
    case "validate": {
      const name = text(testCase, "validator");
      if (!isChecksumName(name)) throw new Error(`unknown validator "${name}"`);
      return { valid: CHECKSUMS[name](text(testCase, "value")) };
    }

    case "detect": {
      const input = text(testCase, "text");
      const matches = detect(
        input,
        strings(testCase, "categories") as PiiCategory[],
        flag(testCase, "strict") ? { "national-id": detectNationalIdStrict } : undefined,
        flag(testCase, "aggressive"),
      );
      return {
        matches: matches.map((match) => ({
          category: match.category,
          value: match.value,
          start: utf16ToCodePoints(input, match.start),
          end: utf16ToCodePoints(input, match.end),
          confidence: match.confidence,
        })),
      };
    }

    case "tokenize": {
      const result = tokenize(text(testCase, "text"), {
        categories: strings(testCase, "categories") as PiiCategory[],
        format: "bracket",
      });
      return { text: result.text, mapping: [...result.mapping] };
    }

    case "detokenize": {
      const result = detokenize(text(testCase, "text"), new Map(pairs(testCase, "mapping")));
      return {
        text: result.text,
        replacedCount: result.replacedCount,
        unresolved: result.unresolved,
      };
    }

    case "shield": {
      const vault = new InMemoryVault(pairs(testCase, "vault"));
      const result = tokenize(text(testCase, "text"), {
        categories: strings(testCase, "categories") as PiiCategory[],
        vault,
      });
      return { text: result.text, vault: vault.entries() };
    }

    case "restore": {
      const result = restore(text(testCase, "text"), new InMemoryVault(pairs(testCase, "vault")));
      return { text: result.text, restored: result.restored, unresolved: result.unresolved };
    }

    case "anonymize": {
      const preset = testCase.input["preset"];
      const rules = testCase.input["rules"];
      const result = anonymize(text(testCase, "text"), {
        ...(preset !== undefined
          ? { preset: strings(testCase, "preset") as CompliancePreset[] }
          : {}),
        ...(rules !== undefined ? { rules: rules as AnonymizationRule[] } : {}),
      });
      return { text: result.text };
    }

    case "preset": {
      const combined = combinePresets(strings(testCase, "names") as CompliancePreset[]);
      return {
        categories: combined.categories,
        defaultStrategy: combined.defaultStrategy,
        rules: combined.rules,
      };
    }

    case "canonicalize":
      return { text: canonicalize(testCase.input["value"]) };

    case "digest":
      return { hex: await sha256Hex(text(testCase, "text")) };

    case "receipt.sign": {
      const key = text(testCase, "key");
      const body = object(testCase, "body");
      const signature = await hmacSha256Hex(
        RECEIPT_DOMAIN + canonicalize(body),
        await hmacKey(key),
      );
      // The library's own verification must agree with the signature computed here.
      const check = await createReceiptIssuer({ key }).verify({ ...body, signature });
      if (!check.valid) throw new Error("anonyma does not verify the signature it should accept");
      return { signature };
    }

    case "receipt.verify": {
      const result = await createReceiptIssuer({ key: text(testCase, "key") }).verify(
        object(testCase, "receipt"),
      );
      return result.valid ? { valid: true } : { valid: false, reason: result.reason };
    }

    case "receipt.issue": {
      const key = text(testCase, "key");
      const at = Date.parse(text(testCase, "timestamp"));
      const presets = testCase.input["presets"];
      const issuer = createReceiptIssuer({
        key,
        now: () => at,
        ...(presets !== undefined
          ? { presets: strings(testCase, "presets") as CompliancePreset[] }
          : {}),
      });
      const receipt = await issuer.issue({
        text: text(testCase, "text"),
        counts: object(testCase, "counts") as Record<string, number>,
      });
      const verified = (await issuer.verify(receipt)).valid;
      return { receipt, verified };
    }
  }
}

/** The TypeScript reference: it provides every capability. */
export const typescriptAdapter: Adapter = {
  name: "typescript",
  provides: () => true,
  run,
};
