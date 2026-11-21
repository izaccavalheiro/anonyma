import { generateText, isStepCount, jsonSchema, streamText, tool, wrapLanguageModel } from "ai";
import { MockLanguageModelV4, convertArrayToReadableStream } from "ai/test";
import { afterEach, describe, expect, it } from "vitest";
import { anonymaMiddleware, createAnonymaAI, withAnonyma } from "../src/index.js";

const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: 0 },
};
const stop = { unified: "stop", raw: "stop" } as const;

/** A model that answers with `text` and records the prompts it was sent. */
function answering(text: string): MockLanguageModelV4 {
  return new MockLanguageModelV4({
    doGenerate: { content: [{ type: "text", text }], finishReason: stop, usage, warnings: [] },
  });
}

/** A model that streams `parts` and records the prompts it was sent. */
function streaming(parts: readonly object[]): MockLanguageModelV4 {
  return new MockLanguageModelV4({
    doStream: async () => ({
      stream: convertArrayToReadableStream([
        { type: "stream-start", warnings: [] },
        ...parts,
        { type: "finish", finishReason: stop, usage },
      ] as never[]),
    }),
  });
}

/** Everything the model was sent, as text. */
function sent(model: MockLanguageModelV4): string {
  return JSON.stringify([...model.doGenerateCalls, ...model.doStreamCalls].map((c) => c.prompt));
}

describe("anonyma-vercel-ai", () => {
  afterEach(() => {
    delete (globalThis as { AI_SDK_DEFAULT_PROVIDER?: unknown }).AI_SDK_DEFAULT_PROVIDER;
  });

  describe("createAnonymaAI", () => {
    it("sanitizes the prompt of generateText and restores the answer", async () => {
      const model = answering("I wrote to [EMAIL_0001] about [PHONE_0001].");
      const anonyma = createAnonymaAI();
      const { text } = await anonyma.generateText({
        model,
        prompt: "Email john@example.com, phone 555-867-5309.",
      });
      expect(text).toBe("I wrote to john@example.com about 555-867-5309.");
      expect(sent(model)).toContain("[EMAIL_0001]");
      expect(sent(model)).not.toContain("john@example.com");
      expect(sent(model)).not.toContain("555-867-5309");
    });

    it("restores a streamed answer and streamed reasoning, tokens split across parts", async () => {
      const model = streaming([
        { type: "reasoning-start", id: "r" },
        { type: "reasoning-delta", id: "r", delta: "The user is [EMA" },
        { type: "reasoning-delta", id: "r", delta: "IL_0001]." },
        { type: "reasoning-end", id: "r" },
        { type: "text-start", id: "t" },
        { type: "text-delta", id: "t", delta: "Sure, [EM" },
        { type: "text-delta", id: "t", delta: "AIL_0001] it is." },
        { type: "text-end", id: "t" },
      ]);
      const result = createAnonymaAI().streamText({ model, prompt: "I am john@example.com" });
      const deltas: string[] = [];
      for await (const delta of result.textStream) deltas.push(delta);
      expect(deltas.join("")).toBe("Sure, john@example.com it is.");
      expect(await result.text).toBe("Sure, john@example.com it is.");
      expect(await result.reasoningText).toBe("The user is john@example.com.");
      expect(sent(model)).not.toContain("john@example.com");
    });

    it("gives tools the real values and the model only tokens", async () => {
      const received: unknown[] = [];
      const model = new MockLanguageModelV4({
        doGenerate: [
          {
            content: [
              {
                type: "tool-call",
                toolCallId: "call-1",
                toolName: "sendMail",
                input: JSON.stringify({ to: "[EMAIL_0001]", body: "Hello" }),
              },
            ],
            finishReason: { unified: "tool-calls", raw: "tool_calls" },
            usage,
            warnings: [],
          },
          {
            content: [{ type: "text", text: "Done: mailed [EMAIL_0001]." }],
            finishReason: stop,
            usage,
            warnings: [],
          },
        ],
      });
      const anonyma = createAnonymaAI();
      const result = await anonyma.generateText({
        model,
        prompt: "Mail john@example.com",
        stopWhen: isStepCount(2),
        tools: {
          sendMail: tool({
            inputSchema: jsonSchema<{ to: string; body: string }>({
              type: "object",
              properties: { to: { type: "string" }, body: { type: "string" } },
              required: ["to", "body"],
            }),
            execute: async (input) => {
              received.push(input);
              return `queued for ${input.to}`;
            },
          }),
        },
      });
      expect(received).toEqual([{ to: "john@example.com", body: "Hello" }]);
      expect(result.text).toBe("Done: mailed john@example.com.");
      // The second step sends the tool result back to the model, tokenized.
      expect(model.doGenerateCalls).toHaveLength(2);
      expect(sent(model)).not.toContain("john@example.com");
      expect(JSON.stringify(model.doGenerateCalls[1]?.prompt)).toContain("queued for [EMAIL_0001]");
    });

    it("passes guard options on: token shape and roles sent unchanged", async () => {
      const model = answering("Hi {{EMAIL_1}}");
      const anonyma = createAnonymaAI({ session: { format: "brace" }, skipRoles: ["system"] });
      const { text } = await anonyma.generateText({
        model,
        system: "Operator: ops@example.com",
        prompt: "I am john@example.com",
      });
      expect(text).toBe("Hi john@example.com");
      expect(sent(model)).toContain("ops@example.com");
      expect(sent(model)).toContain("{{EMAIL_1}}");
    });

    it("wraps a model id string with the configured default provider", async () => {
      const model = answering("ok [EMAIL_0001]");
      const requested: string[] = [];
      (globalThis as { AI_SDK_DEFAULT_PROVIDER?: unknown }).AI_SDK_DEFAULT_PROVIDER = {
        specificationVersion: "v4",
        languageModel: (id: string) => {
          requested.push(id);
          return model;
        },
      };
      const { text } = await createAnonymaAI().generateText({
        model: "mock/model",
        prompt: "john@example.com",
      });
      expect(requested).toEqual(["mock/model"]);
      expect(text).toBe("ok john@example.com");
    });
  });

  describe("withAnonyma", () => {
    it("returns a model that the plain AI SDK functions can use", async () => {
      const model = answering("Reached [EMAIL_0001]");
      const wrapped = withAnonyma(model);
      expect(wrapped.modelId).toBe(model.modelId);
      expect((await generateText({ model: wrapped, prompt: "john@example.com" })).text).toBe(
        "Reached john@example.com",
      );
      const streamed = streaming([
        { type: "text-start", id: "t" },
        { type: "text-delta", id: "t", delta: "[EMAIL_0001]" },
        { type: "text-end", id: "t" },
      ]);
      const result = streamText({ model: withAnonyma(streamed), prompt: "john@example.com" });
      expect(await result.text).toBe("john@example.com");
    });

    it("resolves a model id string", async () => {
      const model = answering("[EMAIL_0001]");
      (globalThis as { AI_SDK_DEFAULT_PROVIDER?: unknown }).AI_SDK_DEFAULT_PROVIDER = {
        specificationVersion: "v4",
        languageModel: () => model,
      };
      const { text } = await generateText({
        model: withAnonyma("mock/model"),
        prompt: "john@example.com",
      });
      expect(text).toBe("john@example.com");
    });
  });

  describe("anonymaMiddleware", () => {
    it("is a v4 middleware for wrapLanguageModel and reports each prompt", async () => {
      const reports: unknown[] = [];
      const middleware = anonymaMiddleware({ onSanitized: (report) => reports.push(report) });
      expect(middleware.specificationVersion).toBe("v4");
      const model = answering("[EMAIL_0001]");
      const wrapped = wrapLanguageModel({ model, middleware });
      const { text } = await generateText({ model: wrapped, prompt: "john@example.com" });
      expect(text).toBe("john@example.com");
      expect(reports).toHaveLength(1);
      expect(reports[0]).toMatchObject({ replaced: 1, unscanned: [] });
    });

    it("lets the report callback stop a request", async () => {
      const model = answering("never");
      const middleware = anonymaMiddleware({
        onSanitized: () => {
          throw new Error("blocked");
        },
      });
      await expect(
        generateText({
          model: wrapLanguageModel({ model, middleware }),
          prompt: "john@example.com",
          maxRetries: 0,
        }),
      ).rejects.toThrow("blocked");
      expect(model.doGenerateCalls).toHaveLength(0);
    });
  });
});

describe("package", () => {
  it("has a changelog section for its version and requires anonyma 1.2", async () => {
    const { readFileSync } = await import("node:fs");
    const read = (name: string) => readFileSync(new URL(`../${name}`, import.meta.url), "utf8");
    const pkg = JSON.parse(read("package.json")) as {
      version: string;
      peerDependencies: Record<string, string>;
    };
    expect(read("CHANGELOG.md")).toContain(`## [${pkg.version}]`);
    expect(pkg.peerDependencies["anonyma"]).toBe("^1.2.0");
  });
});
