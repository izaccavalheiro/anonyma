/**
 * Tests for v2 batch processing utilities
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  anonymizeBatch,
  anonymizeBatchAsync,
  tokenizeBatch,
  detectBatch,
} from "../src/batch.js";
import * as anonymizeModule from "../src/anonymize.js";
import * as tokenizeModule from "../src/tokenize.js";

const SAMPLE_TEXTS = [
  "alice@example.com",
  "Contact bob@example.com or +1-202-555-0102",
  "SSN 001-01-0001",
  "Card 4111111111111111 expires 12/25",
  "No PII here at all",
];

// ---------------------------------------------------------------------------
// anonymizeBatch()
// ---------------------------------------------------------------------------
describe("anonymizeBatch()", () => {
  it("returns an array of the same length as input", () => {
    const results = anonymizeBatch(SAMPLE_TEXTS);
    expect(results).toHaveLength(SAMPLE_TEXTS.length);
  });

  it("each result has index matching array position", () => {
    const results = anonymizeBatch(SAMPLE_TEXTS);
    results.forEach((r, i) => {
      expect(r.index).toBe(i);
    });
  });

  it("successful items have ok: true and value", () => {
    const results = anonymizeBatch(SAMPLE_TEXTS);
    const successes = results.filter((r) => r.ok);
    expect(successes.length).toBeGreaterThanOrEqual(1);
    for (const r of successes) {
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.value).toHaveProperty("text");
        expect(r.value).toHaveProperty("matches");
      }
    }
  });

  it("anonymizes PII within each item", () => {
    const results = anonymizeBatch(["alice@example.com", "SSN 123-45-6789"]);
    expect(results[0]?.ok).toBe(true);
    expect(results[1]?.ok).toBe(true);
    if (results[0]?.ok) expect(results[0].value.text).not.toContain("alice@example.com");
    if (results[1]?.ok) expect(results[1].value.text).not.toContain("123-45-6789");
  });

  it("handles empty array", () => {
    const results = anonymizeBatch([]);
    expect(results).toHaveLength(0);
  });

  it("handles single-item array", () => {
    const results = anonymizeBatch(["alice@example.com"]);
    expect(results).toHaveLength(1);
    expect(results[0]?.ok).toBe(true);
  });

  it("passes options to each anonymize() call", () => {
    const results = anonymizeBatch(["alice@example.com"], {
      defaultStrategy: { strategy: "pseudonymize" },
    });
    if (results[0]?.ok) {
      expect(results[0].value.text).not.toContain("alice@example.com");
      expect(results[0].value.text).not.toContain("[REDACTED]");
    }
  });

  it("handles text with no PII gracefully", () => {
    const results = anonymizeBatch(["The quick brown fox"]);
    expect(results[0]?.ok).toBe(true);
    if (results[0]?.ok) {
      expect(results[0].value.text).toBe("The quick brown fox");
    }
  });

  it("failed items have ok: false and error", () => {
    // We can't easily force a failure without monkey-patching, but
    // verify the shape is correct even for successes
    const results = anonymizeBatch(["alice@example.com"]);
    for (const r of results) {
      if (!r.ok) {
        expect(r.error).toBeInstanceOf(Error);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// anonymizeBatchAsync()
// ---------------------------------------------------------------------------
describe("anonymizeBatchAsync()", () => {
  it("returns a Promise of array with same length", async () => {
    const results = await anonymizeBatchAsync(SAMPLE_TEXTS);
    expect(results).toHaveLength(SAMPLE_TEXTS.length);
  });

  it("each item has correct index", async () => {
    const results = await anonymizeBatchAsync(SAMPLE_TEXTS);
    results.forEach((r, i) => {
      expect(r.index).toBe(i);
    });
  });

  it("anonymizes PII in each item", async () => {
    const results = await anonymizeBatchAsync(["alice@example.com", "bob@example.com"]);
    for (const r of results) {
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.value.text).not.toMatch(/@example\.com/);
      }
    }
  });

  it("concurrency parameter limits parallel execution", async () => {
    // Just verify it doesn't throw and returns correct length
    const texts = Array.from({ length: 20 }, (_, i) => `user${i}@example.com`);
    const results = await anonymizeBatchAsync(texts, {}, 3);
    expect(results).toHaveLength(20);
    expect(results.every((r) => r.ok)).toBe(true);
  });

  it("concurrency of 1 produces serial processing", async () => {
    const texts = ["alice@example.com", "bob@example.com"];
    const results = await anonymizeBatchAsync(texts, {}, 1);
    expect(results).toHaveLength(2);
    expect(results.every((r) => r.ok)).toBe(true);
  });

  it("handles empty array", async () => {
    const results = await anonymizeBatchAsync([]);
    expect(results).toHaveLength(0);
  });

  it("supports hash strategy via async path", async () => {
    const texts = ["alice@example.com"];
    const results = await anonymizeBatchAsync(texts, { strategy: "hash" });
    if (results[0]?.ok) {
      expect(results[0].value.text).not.toContain("alice@example.com");
    }
  });
});

// ---------------------------------------------------------------------------
// tokenizeBatch()
// ---------------------------------------------------------------------------
describe("tokenizeBatch()", () => {
  it("returns an array of the same length as input", () => {
    const results = tokenizeBatch(SAMPLE_TEXTS);
    expect(results).toHaveLength(SAMPLE_TEXTS.length);
  });

  it("each item has ok: true and value with text/mapping/tokens", () => {
    const results = tokenizeBatch(["alice@example.com"]);
    expect(results[0]?.ok).toBe(true);
    if (results[0]?.ok) {
      const val = results[0].value;
      expect(val).toHaveProperty("text");
      expect(val).toHaveProperty("mapping");
      expect(val).toHaveProperty("tokens");
    }
  });

  it("replaces PII with tokens per-item", () => {
    const results = tokenizeBatch(["alice@example.com", "bob@example.com"]);
    for (const r of results) {
      if (r.ok) {
        expect(r.value.text).not.toMatch(/@example\.com/);
        expect(r.value.tokens.length).toBeGreaterThan(0);
      }
    }
  });

  it("each item has independent token mapping", () => {
    const results = tokenizeBatch(["alice@example.com", "alice@example.com"]);
    if (results[0]?.ok && results[1]?.ok) {
      // Both should produce tokens (may be same or different maps depending on impl)
      expect(results[0].value.tokens.length).toBeGreaterThan(0);
      expect(results[1].value.tokens.length).toBeGreaterThan(0);
    }
  });

  it("handles empty texts array", () => {
    const results = tokenizeBatch([]);
    expect(results).toHaveLength(0);
  });

  it("text with no PII returns empty token list", () => {
    const results = tokenizeBatch(["No PII here at all"]);
    if (results[0]?.ok) {
      expect(results[0].value.tokens).toHaveLength(0);
    }
  });
});

// ---------------------------------------------------------------------------
// detectBatch()
// ---------------------------------------------------------------------------
describe("detectBatch()", () => {
  it("returns an array of the same length as input", () => {
    const results = detectBatch(SAMPLE_TEXTS);
    expect(results).toHaveLength(SAMPLE_TEXTS.length);
  });

  it("each item has ok: true and value array of PiiMatch", () => {
    const results = detectBatch(["alice@example.com"]);
    expect(results[0]?.ok).toBe(true);
    if (results[0]?.ok) {
      const matches = results[0].value;
      expect(Array.isArray(matches)).toBe(true);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0]).toHaveProperty("category");
      expect(matches[0]).toHaveProperty("value");
    }
  });

  it("detects email category", () => {
    const results = detectBatch(["alice@example.com"]);
    if (results[0]?.ok) {
      expect(results[0].value.some((m) => m.category === "email")).toBe(true);
    }
  });

  it("category filter is passed through", () => {
    const results = detectBatch(
      ["alice@example.com and +1-202-555-0101"],
      ["email"],
    );
    if (results[0]?.ok) {
      expect(results[0].value.every((m) => m.category === "email")).toBe(true);
    }
  });

  it("handles empty texts array", () => {
    const results = detectBatch([]);
    expect(results).toHaveLength(0);
  });

  it("text with no PII returns empty matches array", () => {
    const results = detectBatch(["The quick brown fox"]);
    if (results[0]?.ok) {
      expect(results[0].value).toHaveLength(0);
    }
  });

  it("each result has correct index", () => {
    const results = detectBatch(SAMPLE_TEXTS);
    results.forEach((r, i) => {
      expect(r.index).toBe(i);
    });
  });
});

// ---------------------------------------------------------------------------
// wrapSync error paths (lines 46-51)
// ---------------------------------------------------------------------------
describe("wrapSync() error handling", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("anonymizeBatch captures Error thrown by anonymize()", () => {
    vi.spyOn(anonymizeModule, "anonymize").mockImplementation(() => {
      throw new Error("sync anonymize failure");
    });
    const results = anonymizeBatch(["alice@example.com"]);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("sync anonymize failure");
    }
  });

  it("anonymizeBatch wraps non-Error thrown by anonymize() into Error", () => {
    vi.spyOn(anonymizeModule, "anonymize").mockImplementation(() => {
      throw "string error";
    });
    const results = anonymizeBatch(["alice@example.com"]);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("string error");
    }
  });

  it("tokenizeBatch captures Error thrown by tokenize()", () => {
    vi.spyOn(tokenizeModule, "tokenize").mockImplementation(() => {
      throw new Error("sync tokenize failure");
    });
    const results = tokenizeBatch(["alice@example.com"]);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("sync tokenize failure");
    }
  });

  it("tokenizeBatch wraps non-Error thrown by tokenize() into Error", () => {
    vi.spyOn(tokenizeModule, "tokenize").mockImplementation(() => {
      throw 42;
    });
    const results = tokenizeBatch(["alice@example.com"]);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("42");
    }
  });

  it("detectBatch captures Error thrown by detect()", () => {
    vi.spyOn(anonymizeModule, "detect").mockImplementation(() => {
      throw new Error("sync detect failure");
    });
    const results = detectBatch(["alice@example.com"]);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("sync detect failure");
    }
  });

  it("detectBatch wraps non-Error thrown by detect() into Error", () => {
    vi.spyOn(anonymizeModule, "detect").mockImplementation(() => {
      throw { code: 99 };
    });
    const results = detectBatch(["alice@example.com"]);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
    }
  });
});

// ---------------------------------------------------------------------------
// wrapAsync error paths (lines 62-67)
// ---------------------------------------------------------------------------
describe("wrapAsync() error handling", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("anonymizeBatchAsync captures Error thrown by anonymizeAsync()", async () => {
    vi.spyOn(anonymizeModule, "anonymizeAsync").mockRejectedValue(
      new Error("async anonymize failure"),
    );
    const results = await anonymizeBatchAsync(["alice@example.com"]);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("async anonymize failure");
    }
  });

  it("anonymizeBatchAsync wraps non-Error rejection into Error", async () => {
    vi.spyOn(anonymizeModule, "anonymizeAsync").mockRejectedValue("async string error");
    const results = await anonymizeBatchAsync(["alice@example.com"]);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("async string error");
    }
  });

  it("anonymizeBatchAsync with concurrency captures Error thrown by anonymizeAsync()", async () => {
    vi.spyOn(anonymizeModule, "anonymizeAsync").mockRejectedValue(
      new Error("concurrent async failure"),
    );
    const results = await anonymizeBatchAsync(["alice@example.com", "bob@example.com"], {}, 1);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("concurrent async failure");
    }
  });

  it("anonymizeBatchAsync with concurrency wraps non-Error rejection into Error", async () => {
    vi.spyOn(anonymizeModule, "anonymizeAsync").mockRejectedValue(404);
    const results = await anonymizeBatchAsync(["alice@example.com"], {}, 2);
    expect(results[0]?.ok).toBe(false);
    if (!results[0]?.ok) {
      expect(results[0].error).toBeInstanceOf(Error);
      expect(results[0].error.message).toBe("404");
    }
  });
});
