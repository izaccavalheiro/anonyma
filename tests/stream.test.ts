/**
 * Tests for src/stream.ts — targets 100 % code coverage.
 *
 * All four exported symbols are exercised:
 *   - createAnonymizeStream
 *   - createAnonymizeStreamAsync
 *   - createTokenizeStream
 *   - requireTransformStream (indirectly via the three factory functions, and
 *     directly by temporarily deleting the global)
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  createAnonymizeStream,
  createAnonymizeStreamAsync,
  createTokenizeStream,
} from "../src/stream.js";
import { ValidationError } from "../src/errors.js";

// ---------------------------------------------------------------------------
// Helper: push one chunk through a TransformStream and collect the output.
// Write and read are started concurrently to avoid backpressure deadlock.
// ---------------------------------------------------------------------------
async function pushThrough<I, O>(
  stream: TransformStream<I, O>,
  chunk: I,
): Promise<O> {
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();

  const [, result] = await Promise.all([
    writer.write(chunk).then(() => writer.close()),
    reader.read(),
  ]);
  return (result as ReadableStreamReadValueResult<O>).value;
}

// Helper: push a chunk and capture the error that the stream surfaces.
async function pushThroughExpectError<I, O>(
  stream: TransformStream<I, O>,
  chunk: I,
): Promise<unknown> {
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();

  // Start the read first so the readable side is ready to receive errors.
  const readPromise = reader.read().then(
    () => {
      throw new Error("Expected stream to error but it resolved");
    },
    (err: unknown) => err,
  );

  // Writing the bad chunk — the writer may also reject.
  try {
    await writer.write(chunk);
  } catch {
    // swallow — the error propagates to the readable side.
  }

  return readPromise;
}

// ---------------------------------------------------------------------------
// createAnonymizeStream
// ---------------------------------------------------------------------------
describe("createAnonymizeStream", () => {
  it("anonymizes a plain string chunk", async () => {
    const stream = createAnonymizeStream();
    const result = await pushThrough(stream, "alice@example.com");

    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("matches");
    expect((result as { text: string }).text).not.toContain("alice@example.com");
  });

  it("passes anonymization options to the underlying anonymize()", async () => {
    const stream = createAnonymizeStream({
      defaultStrategy: { strategy: "mask" },
    });
    const result = await pushThrough(stream, "alice@example.com");
    expect((result as { text: string }).text).toMatch(/\*/);
  });

  it("returns text unchanged when no PII is present", async () => {
    const stream = createAnonymizeStream();
    const result = await pushThrough(stream, "Hello world");
    expect((result as { text: string }).text).toBe("Hello world");
  });

  it("surfaces a ValidationError when chunk is not a string", async () => {
    const stream = createAnonymizeStream();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = await pushThroughExpectError(stream, 42 as any);
    expect(err).toBeInstanceOf(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// createAnonymizeStreamAsync
// ---------------------------------------------------------------------------
describe("createAnonymizeStreamAsync", () => {
  it("async-anonymizes a plain string chunk", async () => {
    const stream = createAnonymizeStreamAsync();
    const result = await pushThrough(stream, "alice@example.com");

    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("matches");
    expect((result as { text: string }).text).not.toContain("alice@example.com");
  });

  it("passes options to the underlying anonymizeAsync()", async () => {
    const stream = createAnonymizeStreamAsync({
      defaultStrategy: { strategy: "redact" },
    });
    const result = await pushThrough(stream, "bob@example.com");
    expect((result as { text: string }).text).toContain("[REDACTED]");
  });

  it("returns text unchanged when no PII is present", async () => {
    const stream = createAnonymizeStreamAsync();
    const result = await pushThrough(stream, "No PII here");
    expect((result as { text: string }).text).toBe("No PII here");
  });

  it("surfaces a ValidationError when chunk is not a string", async () => {
    const stream = createAnonymizeStreamAsync();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = await pushThroughExpectError(stream, 99 as any);
    expect(err).toBeInstanceOf(ValidationError);
  });

  it("propagates errors thrown by anonymizeAsync()", async () => {
    // Patch anonymizeAsync to throw so we can exercise the catch branch.
    const streamModule = await import("../src/stream.js");
    const anonymizeModule = await import("../src/anonymize.js");

    const spy = vi
      .spyOn(anonymizeModule, "anonymizeAsync")
      .mockRejectedValueOnce(new Error("async boom"));

    // Re-create the stream AFTER the spy is in place so the patched module
    // is used during the transform.
    const stream = streamModule.createAnonymizeStreamAsync();
    const err = await pushThroughExpectError(stream, "some text");

    expect((err as Error).message).toBe("async boom");
    spy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// createTokenizeStream
// ---------------------------------------------------------------------------
describe("createTokenizeStream", () => {
  it("tokenizes a plain string chunk", async () => {
    const stream = createTokenizeStream();
    const result = await pushThrough(stream, "Contact alice@example.com");

    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("mapping");
    expect(result).toHaveProperty("tokens");
    expect((result as { text: string }).text).not.toContain("alice@example.com");
  });

  it("passes tokenization options to the underlying tokenize()", async () => {
    const stream = createTokenizeStream({ categories: ["email"] });
    const result = await pushThrough(stream, "alice@example.com calls 555-867-5309");
    // Phone should NOT be tokenized since we restricted to email only.
    expect((result as { text: string }).text).toContain("555-867-5309");
    expect((result as { text: string }).text).not.toContain("alice@example.com");
  });

  it("returns text unchanged when no PII is present", async () => {
    const stream = createTokenizeStream();
    const result = await pushThrough(stream, "Plain text");
    expect((result as { text: string }).text).toBe("Plain text");
  });

  it("surfaces a ValidationError when chunk is not a string", async () => {
    const stream = createTokenizeStream();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = await pushThroughExpectError(stream, true as any);
    expect(err).toBeInstanceOf(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// requireTransformStream — unavailable environment branch
// ---------------------------------------------------------------------------
describe("requireTransformStream (unavailable environment)", () => {
  afterEach(() => {
    // Ensure TransformStream is restored even if the test throws.
    if (typeof (globalThis as Record<string, unknown>).TransformStream === "undefined") {
      (globalThis as Record<string, unknown>).TransformStream = TransformStream;
    }
  });

  it("throws ValidationError when TransformStream is not defined globally", () => {
    const saved = (globalThis as Record<string, unknown>).TransformStream;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (globalThis as any).TransformStream;

    try {
      expect(() => createAnonymizeStream()).toThrow(ValidationError);
      expect(() => createAnonymizeStreamAsync()).toThrow(ValidationError);
      expect(() => createTokenizeStream()).toThrow(ValidationError);
    } finally {
      (globalThis as Record<string, unknown>).TransformStream = saved;
    }
  });
});
