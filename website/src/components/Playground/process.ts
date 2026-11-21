/**
 * @module playground/process
 * @description What the playground does with a text: one function from the
 * text and the settings on the page to the output, the findings and the
 * counts. It runs in the browser; nothing here reaches the network. The root
 * test suite runs it against the library's source (tests/playground.test.ts).
 */

import { combinePresets } from "anonyma";
import type { CompliancePreset } from "anonyma";
import { compilePipeline } from "anonyma/engine";
import type { PipelineSpec, StrategySpec } from "anonyma/engine";
import { InMemoryVault, createVaultTokenizer, restore } from "anonyma/vault";

/** How detected values are replaced. `"preset"` keeps the strategies of the selected presets. */
export type Mode = "preset" | "redact" | "mask" | "pseudonymize" | "synthesize" | "tokenize";

/** The settings on the page. */
export interface Settings {
  readonly presets: readonly CompliancePreset[];
  readonly mode: Mode;
  /** `"precise"`: validating detectors (check digits); `"legacy"`: the 1.x detectors. */
  readonly detection: "precise" | "legacy";
}

/** One replaced value. */
export interface Finding {
  readonly category: string;
  readonly confidence: number;
  /** The detected text, as typed into the page. */
  readonly value: string;
  readonly replacement: string;
  /** Offsets of the replacement in the output. */
  readonly outStart: number;
  readonly outEnd: number;
}

/** What processing a text gives. */
export interface Outcome {
  readonly text: string;
  readonly findings: readonly Finding[];
  /** Number of replaced values per category, most frequent first. */
  readonly counts: readonly (readonly [string, number])[];
  /** For `tokenize`: the vault, token by token, and the output with the values put back. */
  readonly vault?: readonly (readonly [string, string])[];
  readonly restored?: string;
  /** Milliseconds the transformation took. */
  readonly millis: number;
}

const STRATEGIES: Readonly<Record<Exclude<Mode, "preset" | "tokenize">, StrategySpec>> = {
  redact: { strategy: "redact" },
  mask: { strategy: "mask", keepTrailing: 4 },
  pseudonymize: { strategy: "pseudonymize" },
  synthesize: { strategy: "synthesize" },
};

function specOf(settings: Settings): PipelineSpec {
  const { presets, mode, detection } = settings;
  const base: PipelineSpec = { detection };
  if (mode === "preset") return presets.length > 0 ? { ...base, preset: presets } : base;
  // One strategy for every category, so the presets give their categories only.
  const categories = presets.length > 0 ? combinePresets(presets).categories : undefined;
  return {
    ...base,
    ...(categories !== undefined ? { categories } : {}),
    defaultStrategy: mode === "tokenize" ? { strategy: "tokenize" } : STRATEGIES[mode],
  };
}

/**
 * Process a text with the settings of the page.
 *
 * @param text - The text typed or pasted into the page.
 * @param settings - Presets, replacement mode and detection.
 * @param now - Clock, for the timing shown on the page.
 * @returns The output, the findings and the counts.
 */
export function processText(
  text: string,
  settings: Settings,
  now: () => number = Date.now,
): Outcome {
  const vault = settings.mode === "tokenize" ? new InMemoryVault() : undefined;
  const pipeline = compilePipeline(
    specOf(settings),
    vault === undefined ? {} : { tokenization: createVaultTokenizer({ vault }) },
  );
  const started = now();
  const result = pipeline.transform(text);
  const millis = now() - started;

  const counts = new Map<string, number>();
  const findings = result.spans.map((span) => {
    counts.set(span.category, (counts.get(span.category) ?? 0) + 1);
    return {
      category: span.category,
      confidence: span.confidence,
      value: text.slice(span.start, span.end),
      replacement: result.text.slice(span.outStart, span.outEnd),
      outStart: span.outStart,
      outEnd: span.outEnd,
    };
  });
  const sorted = [...counts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));

  if (vault === undefined) return { text: result.text, findings, counts: sorted, millis };
  return {
    text: result.text,
    findings,
    counts: sorted,
    vault: vault.entries().map(([token, value]) => [token, value] as const),
    restored: restore(result.text, vault).text,
    millis,
  };
}

/** A sample of synthetic personal data from several countries. */
export const SAMPLE = `Olá! Meu CPF é 529.982.247-25 e o celular (11) 91234-5678.
Envie a nota para ana.souza@example.com — empresa 11.222.333/0001-81.
Shipping address: Musterstraße 12, 10115 Berlin. Card 4111 1111 1111 1111, exp 12/29.
IBAN GB82 WEST 1234 5698 7654 32 · NINO AB 12 34 56 C · SSN 219-09-9999.
Server 192.0.2.10 rejected a login from 2001:db8::7 at 10:42.`;
