/**
 * The logic of the web playground (playground/src/process.ts), which runs in
 * the browser on the library's source.
 */
import { describe, expect, it } from "vitest";
import { SAMPLE, processText } from "../playground/src/process.js";

describe("playground", () => {
  it("replaces the sample's personal data with the presets' strategies", () => {
    const outcome = processText(SAMPLE, { presets: [], mode: "preset", detection: "precise" });
    for (const value of [
      "529.982.247-25",
      "ana.souza@example.com",
      "4111 1111 1111 1111",
      "192.0.2.10",
    ]) {
      expect(outcome.text).not.toContain(value);
    }
    expect(outcome.findings.length).toBeGreaterThan(8);
    expect(outcome.counts[0]?.[1]).toBeGreaterThanOrEqual(outcome.counts.at(-1)?.[1] ?? 0);
    expect(outcome.vault).toBeUndefined();
    const [first] = outcome.findings;
    expect(outcome.text.slice(first?.outStart, first?.outEnd)).toBe(first?.replacement);
  });

  it("uses the strategies of combined presets", () => {
    const text = "Card 4111 1111 1111 1111";
    const pci = processText(text, { presets: ["pci-dss"], mode: "preset", detection: "precise" });
    expect(pci.text).toMatch(/1111$/);
    const both = processText(text, {
      presets: ["pci-dss", "hipaa"],
      mode: "preset",
      detection: "precise",
    });
    expect(both.text).toBe("Card [REDACTED]");
  });

  it("applies one strategy to the categories of the presets", () => {
    const text = "ana@example.com 4111 1111 1111 1111";
    const masked = processText(text, { presets: ["pci-dss"], mode: "mask", detection: "precise" });
    expect(masked.text).toMatch(/^\*+\.com \*+1111$/);
    const all = processText(text, { presets: [], mode: "redact", detection: "precise" });
    expect(all.text).toBe("[REDACTED] [REDACTED]");
    for (const mode of ["pseudonymize", "synthesize"] as const) {
      expect(processText(text, { presets: [], mode, detection: "precise" }).text).not.toContain(
        "ana@example.com",
      );
    }
  });

  it("tokenizes into a vault and puts the values back", () => {
    const text = "Mail ana@example.com, then ana@example.com again";
    const outcome = processText(text, { presets: [], mode: "tokenize", detection: "precise" });
    expect(outcome.text).toBe("Mail {{EMAIL_1}}, then {{EMAIL_1}} again");
    expect(outcome.vault).toEqual([["{{EMAIL_1}}", "ana@example.com"]]);
    expect(outcome.restored).toBe(text);
  });

  it("lets check digits decide only with the validating detectors", () => {
    const text = "CPF 529.982.247-26";
    expect(processText(text, { presets: [], mode: "redact", detection: "precise" }).text).toBe(
      text,
    );
    expect(processText(text, { presets: [], mode: "redact", detection: "legacy" }).text).toBe(
      "CPF [REDACTED]",
    );
  });

  it("times the transformation with the clock it is given", () => {
    let tick = 0;
    const outcome = processText(
      "x",
      { presets: [], mode: "redact", detection: "precise" },
      () => (tick += 5),
    );
    expect(outcome.millis).toBe(5);
    expect(
      processText("x", { presets: [], mode: "redact", detection: "precise" }).millis,
    ).toBeGreaterThanOrEqual(0);
  });
});
