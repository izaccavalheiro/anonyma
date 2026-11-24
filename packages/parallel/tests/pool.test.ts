/**
 * The pool returns what anonyma's batch functions return in one thread: the
 * same entries, in the same order, with the same indexes. Small chunks spread
 * each batch over many workers.
 */
import { anonymizeBatch, detectBatch } from "anonyma";
import { compilePipeline } from "anonyma/engine";
import { afterAll, describe, expect, it } from "vitest";

// The built package: its pool starts dist/worker.js in each thread (npm test builds it
// first). The types are the source's, which the build was made from.
const built = new URL("../dist/index.js", import.meta.url).href;
const { PoolOptionsError, createPool } = (await import(built)) as typeof import("../src/index.js");

/** Synthetic lines: values of several categories, labels, and lines without data. */
const LINES = Array.from(
  { length: 600 },
  (_, i) =>
    [
      `2026-11-24 INFO request ${String(i)} for user${String(i)}@example.com`,
      `Card 4111 1111 1111 1111, passport: A${String(1000000 + i)}`,
      `nothing to see in line ${String(i)}`,
      `Dear Ana Example, call +1 202 555 0${String(100 + (i % 900)).padStart(3, "0")}`,
      `IBAN DE89370400440532013000 and 192.0.2.${String(i % 250)}`,
    ][i % 5] ?? "",
);

// Every batch goes to the workers, in small chunks spread over many of them.
const pool = createPool({ threads: 3, chunkSize: 2000, inlineBelow: 0 });
afterAll(() => pool.close());

describe("anonyma-parallel", () => {
  it("detects as detectBatch() does, in order", async () => {
    expect(await pool.detectBatch(LINES)).toEqual(detectBatch(LINES));
    expect(await pool.detectBatch(LINES, ["email", "ipv4"])).toEqual(
      detectBatch(LINES, ["email", "ipv4"]),
    );
  });

  it("anonymizes as anonymizeBatch() does, in order", async () => {
    const options = {
      preset: "gdpr" as const,
      rules: [{ category: "email" as const, strategy: { strategy: "mask" as const } }],
      includeMatches: true,
      customPatterns: [{ pattern: /line \d+/, replacement: "[LINE]" }],
    };
    // Unseeded pseudonyms differ on every call: compare everything else.
    const strip = (results: Awaited<ReturnType<typeof pool.anonymizeBatch>>) =>
      results.map((r) =>
        r.ok ? { ...r, value: { ...r.value, text: r.value.text.replace(/id_\w+/g, "id_") } } : r,
      );
    expect(strip(await pool.anonymizeBatch(LINES, options))).toEqual(
      strip(anonymizeBatch(LINES, options)),
    );
    const results = await pool.anonymizeBatch(LINES);
    expect(results.map((r) => r.index)).toEqual(LINES.map((_, i) => i));
  });

  it("scans as compilePipeline(spec).scanBatch() does", async () => {
    expect(await pool.scanBatch(LINES)).toEqual(compilePipeline({}).scanBatch(LINES));
    expect(await pool.scanBatch(LINES, { categories: ["email"] })).toEqual(
      compilePipeline({ categories: ["email"] }).scanBatch(LINES),
    );
  });

  it("keeps a failing entry in its place", async () => {
    const texts = ["a ana@example.com", 7 as unknown as string, "b"];
    const results = await pool.detectBatch(texts);
    expect(results.map((r) => [r.index, r.ok])).toEqual([
      [0, true],
      [1, false],
      [2, true],
    ]);
    const failed = results[1];
    expect(failed?.ok === false && failed.error.message).toBe(
      (detectBatch(texts)[1] as { error: Error }).error.message,
    );
  });

  it("handles empty batches and reports errors of the call", async () => {
    expect(await pool.detectBatch([])).toEqual([]);
    await expect(pool.scanBatch(["x"], { preset: ["nope" as "gdpr"] })).rejects.toThrow();
    await expect(pool.detectBatch("x" as unknown as string[])).rejects.toThrow(TypeError);
    // The pool still works after a failed call.
    expect(await pool.detectBatch(["ana@example.com"])).toEqual(detectBatch(["ana@example.com"]));
  });

  it("refuses options a worker cannot receive", async () => {
    await expect(
      pool.anonymizeBatch(LINES, { customDetectors: { email: () => [] } }),
    ).rejects.toThrow(PoolOptionsError);
  });

  it("runs a small batch in the calling thread, with the same results", async () => {
    const own = createPool({ threads: 2 });
    const small = LINES.slice(0, 20);
    expect(own.explain(small)).toEqual({
      route: "inline",
      characters: small.join("").length,
      chunks: 1,
      threads: 0,
    });
    expect(await own.detectBatch(small)).toEqual(detectBatch(small));
    expect(await own.detectBatch(small, ["email"])).toEqual(detectBatch(small, ["email"]));
    expect((await own.anonymizeBatch(small, { preset: "pci-dss" })).map((r) => r.ok)).toEqual(
      small.map(() => true),
    );
    expect(await own.scanBatch(small)).toEqual(compilePipeline({}).scanBatch(small));
    await expect(own.scanBatch(["x"], { preset: ["nope" as "gdpr"] })).rejects.toThrow();
    await own.close();
  });

  it("explains how a batch would run", () => {
    expect(pool.explain(LINES)).toMatchObject({ route: "workers", threads: 3 });
    expect(pool.explain(LINES).chunks).toBeGreaterThan(3);
    expect(pool.explain("x" as unknown as string[])).toMatchObject({ characters: 0 });
    const big = createPool({ threads: 2 });
    expect(big.explain([...LINES, ...LINES, ...LINES])).toMatchObject({
      route: "workers",
      chunks: 2,
      threads: 2,
    });
    return big.close();
  });

  it("closes, and refuses calls afterwards", async () => {
    const own = createPool({ threads: 1 });
    expect(own.threads).toBe(1);
    expect(await own.detectBatch(LINES.slice(0, 5))).toEqual(detectBatch(LINES.slice(0, 5)));
    await own.close();
    await own.close();
    await expect(own.detectBatch(["x"])).rejects.toThrow(/closed/);
  });

  it("defaults to one thread per core but one", () => {
    const own = createPool();
    expect(own.threads).toBeGreaterThanOrEqual(1);
    return own.close();
  });
});
