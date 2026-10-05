import { describe, expect, it } from "vitest";
import { AsyncStrategyError, ValidationError } from "../../src/errors.js";
import {
  compilePipeline,
  constant,
  createAsyncChunkTransformer,
  createChunkTransformer,
  createPipeline,
  createPipelineStream,
  defineRegexDetector,
  emailDetector,
  redactWith,
} from "../../src/engine/index.js";
import type { ReplaceContext } from "../../src/engine/index.js";

const TEXT =
  "Contact alice@example.com or call 555-867-5309, SSN 123-45-6789, card 4111 1111 1111 1111.";

function chunksOf(text: string, size: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out;
}

async function pipeThrough(
  stream: TransformStream<string, string>,
  chunks: unknown[],
): Promise<string> {
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();
  const writing = (async () => {
    for (const chunk of chunks) await writer.write(chunk as string);
    await writer.close();
  })();
  const reading = (async () => {
    let out = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return out;
      out += value;
    }
  })();
  const [out] = await Promise.all([reading, writing]);
  return out;
}

describe("engine/stream", () => {
  describe("createChunkTransformer", () => {
    const pipeline = compilePipeline();
    const whole = pipeline.transform(TEXT).text;

    it("gives the whole-text result for every chunk size, including one character", () => {
      for (const size of [1, 2, 3, 5, 8, 16, 40, 1000]) {
        const transformer = createChunkTransformer(pipeline, { batch: size % 2 === 0 ? 0 : 4096 });
        let out = "";
        for (const chunk of chunksOf(TEXT, size)) out += transformer.push(chunk);
        out += transformer.flush();
        expect(out, `chunk size ${String(size)}`).toBe(whole);
      }
    });

    it("detects a value that is split across two chunks", () => {
      const transformer = createChunkTransformer(compilePipeline({ categories: ["email"] }));
      const out =
        transformer.push("contact alice@exam") +
        transformer.push("ple.com now") +
        transformer.flush();
      expect(out).toBe("contact [REDACTED] now");
    });

    it("emits settled text before the end of the input and holds back at most a window", () => {
      const transformer = createChunkTransformer(compilePipeline({ categories: ["email"] }), {
        window: 32,
        batch: 0,
      });
      const filler = "lorem ipsum dolor sit amet ".repeat(8);
      const early = transformer.push(filler);
      expect(early.length).toBe(filler.length - 32);
      expect(early + transformer.flush()).toBe(filler);
    });

    it("holds a detection back until it is complete", () => {
      const url = defineRegexDetector({ category: "url", pattern: /https:\/\/\S+/ });
      const transformer = createChunkTransformer(
        createPipeline({ detectors: [url], replace: { fallback: constant("<url>") } }),
        { window: 8, batch: 0 },
      );
      let out = transformer.push("see https://example.com/a/very/long/path");
      expect(out).toBe("see ");
      out += transformer.push("/that/keeps/growing and more text after it");
      out += transformer.flush();
      expect(out).toBe("see <url> and more text after it");
    });

    it("replaces only the visible remainder of a detection longer than the window", () => {
      // Documented limit: the window must be at least as long as the longest detection.
      const transformer = createChunkTransformer(
        createPipeline({ detectors: [emailDetector], replace: { fallback: constant("#") } }),
        { window: 4, batch: 0 },
      );
      const out =
        transformer.push("xx alice@") + transformer.push("example.com yy") + transformer.flush();
      expect(out).not.toContain("example.com");
      expect(out.endsWith(" yy")).toBe(true);
    });

    it("never splits a surrogate pair between two outputs", () => {
      const transformer = createChunkTransformer(compilePipeline({ categories: ["email"] }), {
        window: 3,
        batch: 0,
      });
      const text = "ab😀cd😀ef😀gh";
      let out = "";
      for (const ch of text) {
        const piece = transformer.push(ch);
        expect(/[\ud800-\udbff]$/.test(piece)).toBe(false);
        out += piece;
      }
      expect(out + transformer.flush()).toBe(text);
    });

    it("numbers replacements and reports offsets relative to the whole stream", () => {
      const contexts: ReplaceContext[] = [];
      const transformer = createChunkTransformer(
        createPipeline({
          detectors: [emailDetector],
          replace: {
            fallback: (_value, context) => {
              contexts.push(context);
              return "#";
            },
          },
        }),
        { window: 24, batch: 0 },
      );
      const text = `${"x".repeat(100)} a@example.com ${"y".repeat(100)} b@example.com`;
      let out = "";
      for (const chunk of chunksOf(text, 7)) out += transformer.push(chunk);
      out += transformer.flush();
      expect(out).toBe(`${"x".repeat(100)} # ${"y".repeat(100)} #`);
      expect(contexts.map((c) => [c.ordinal, c.start, c.end, text.slice(c.start, c.end)])).toEqual([
        [0, 101, 114, "a@example.com"],
        [1, 216, 229, "b@example.com"],
      ]);
    });

    it("waits for a batch of new input before scanning again", () => {
      const transformer = createChunkTransformer(compilePipeline({ categories: ["email"] }), {
        window: 16,
        batch: 64,
        tokenLimit: 0,
      });
      expect(transformer.push("x".repeat(79))).toBe("");
      expect(transformer.push("x")).toBe("x".repeat(64));
      expect(transformer.flush()).toBe("x".repeat(16));
    });

    it("holds an unbroken token back until it ends, so a long secret is never emitted in part", () => {
      const pipeline = compilePipeline();
      const jwt = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTg4NDEi${"QUJDREVGR0hJSktM".repeat(40)}.${"c2lnbmF0dXJl".repeat(4)}`;
      const text = `${"lorem ipsum ".repeat(300)}token ${jwt} end`;
      const transformer = createChunkTransformer(pipeline);
      let out = "";
      for (const chunk of chunksOf(text, 64)) out += transformer.push(chunk);
      out += transformer.flush();
      expect(out).toBe(pipeline.transform(text).text);
      expect(out).not.toContain("eyJhbGci");
    });

    it("stops holding a token back once it is longer than the token limit", () => {
      const transformer = createChunkTransformer(compilePipeline({ categories: ["email"] }), {
        window: 8,
        batch: 0,
        tokenLimit: 32,
      });
      expect(transformer.push("x".repeat(30))).toBe("");
      expect(transformer.push("x".repeat(30)).length).toBe(52);
      expect(() =>
        createChunkTransformer(compilePipeline({ categories: ["email"] }), { tokenLimit: -1 }),
      ).toThrow(ValidationError);
    });

    it("starts a new text after flush()", () => {
      const transformer = createChunkTransformer(compilePipeline({ categories: ["ssn"] }), {
        batch: 0,
      });
      expect(transformer.push("Order 20241234") + transformer.flush()).toBe("Order 20241234");
      expect(transformer.push("123-45-6789 is my SSN") + transformer.flush()).toBe(
        "[REDACTED] is my SSN",
      );
    });

    it("replaces a detection that ends on a high surrogate exactly once", () => {
      const pipeline = createPipeline({
        detectors: [defineRegexDetector({ category: "id", pattern: /ID-.{3}/, maxMatchLength: 8 })],
        replace: { fallback: constant("#") },
      });
      const text = "aaaaaaaaaaaa ID-ab\u{1F600} bbbbbbbbbbbbbbbbbbbb";
      const whole = pipeline.transform(text).text;
      for (const size of [1, 2, 3, 5, 7]) {
        const transformer = createChunkTransformer(pipeline, { batch: 0 });
        let out = "";
        for (const chunk of chunksOf(text, size)) out += transformer.push(chunk);
        expect(out + transformer.flush(), String(size)).toBe(whole);
      }
    });

    it("rescans a growing detection a logarithmic number of times", () => {
      let scans = 0;
      const url = defineRegexDetector({ category: "url", pattern: /https:\/\/\S+/ });
      const pipeline = createPipeline({
        detectors: [url],
        replace: { fallback: constant("<url>") },
      });
      const counting = { ...pipeline, scan: (text: string) => (scans++, pipeline.scan(text)) };
      const transformer = createChunkTransformer(counting);
      const text = `see https://files.example.com/download?token=${"a".repeat(80_000)} end`;
      let out = "";
      for (const chunk of chunksOf(text, 16)) out += transformer.push(chunk);
      expect(out + transformer.flush()).toBe("see <url> end");
      expect(scans).toBeLessThan(40);
    });

    it("returns nothing for empty pushes and an empty stream", () => {
      const transformer = createChunkTransformer(pipeline);
      expect(transformer.push("")).toBe("");
      expect(transformer.flush()).toBe("");
      expect(transformer.flush()).toBe("");
    });

    it("rejects non-string chunks, bad windows and asynchronous replacers", () => {
      expect(() => createChunkTransformer(pipeline).push(1 as unknown as string)).toThrow(
        ValidationError,
      );
      for (const window of [0, -1, 1.5]) {
        expect(() => createChunkTransformer(pipeline, { window })).toThrow(ValidationError);
      }
      for (const batch of [-1, 1.5]) {
        expect(() => createChunkTransformer(pipeline, { batch })).toThrow(ValidationError);
      }
      const asyncPipeline = createPipeline({
        detectors: [emailDetector],
        replace: { fallback: () => Promise.resolve("#") },
      });
      const transformer = createChunkTransformer(asyncPipeline);
      transformer.push("a@example.com");
      expect(() => transformer.flush()).toThrow(AsyncStrategyError);
    });

    it("falls back to a default window for detectors without a length bound", () => {
      const unbounded = defineRegexDetector({ category: "word", pattern: /secret/ });
      const transformer = createChunkTransformer(
        createPipeline({ detectors: [unbounded], replace: { fallback: redactWith() } }),
        { batch: 0, tokenLimit: 0 },
      );
      const text = "a".repeat(300);
      expect(transformer.push(text).length).toBe(300 - 256);
    });
  });

  describe("createAsyncChunkTransformer", () => {
    it("awaits asynchronous replacers and matches the whole-text result", async () => {
      const pipeline = compilePipeline({ defaultStrategy: { strategy: "hash" } });
      const whole = (await pipeline.transformAsync(TEXT)).text;
      for (const size of [1, 7, 64]) {
        const transformer = createAsyncChunkTransformer(pipeline);
        let out = "";
        for (const chunk of chunksOf(TEXT, size)) out += await transformer.push(chunk);
        out += await transformer.flush();
        expect(out).toBe(whole);
      }
    });
  });

  describe("createPipelineStream", () => {
    it("transforms a stream of arbitrary chunks into plain strings", async () => {
      const pipeline = compilePipeline();
      const out = await pipeThrough(createPipelineStream(pipeline), chunksOf(TEXT, 9));
      expect(out).toBe(pipeline.transform(TEXT).text);
    });

    it("produces no empty chunks and handles an empty stream", async () => {
      const stream = createPipelineStream(compilePipeline());
      const writer = stream.writable.getWriter();
      const reader = stream.readable.getReader();
      void writer.write("short").then(() => writer.close());
      const seen: string[] = [];
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        seen.push(value);
      }
      expect(seen).toEqual(["short"]);
      expect(await pipeThrough(createPipelineStream(compilePipeline()), [])).toBe("");
    });

    it("errors the stream on a non-string chunk", async () => {
      await expect(
        pipeThrough(createPipelineStream(compilePipeline()), [new Uint8Array(2)]),
      ).rejects.toThrow(ValidationError);
    });

    it("fails when TransformStream is unavailable", () => {
      const original = globalThis.TransformStream;
      // @ts-expect-error -- simulate a runtime without the Streams API
      delete globalThis.TransformStream;
      try {
        expect(() => createPipelineStream(compilePipeline())).toThrow(ValidationError);
      } finally {
        globalThis.TransformStream = original;
      }
    });
  });
});
