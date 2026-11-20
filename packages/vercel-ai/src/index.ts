/**
 * @module @anonyma/vercel-ai
 * @description Personal-data redaction for the Vercel AI SDK. Prompts are
 * sanitized before they leave the process — personal data becomes tokens
 * such as `[EMAIL_0001]` — and the tokens are replaced by the original values
 * in what the model returns: the text, the reasoning, the arguments of tool
 * calls, complete or streamed. The mapping between tokens and values never
 * leaves the process.
 *
 * @example
 * ```ts
 * import { openai } from "@ai-sdk/openai";
 * import { createAnonymaAI } from "@anonyma/vercel-ai";
 *
 * const anonyma = createAnonymaAI({ skipRoles: ["system"] });
 * const { text } = await anonyma.generateText({
 *   model: openai("gpt-5"),
 *   prompt: "Write a reply to john@example.com about invoice 42.",
 * });
 * // The model saw "[EMAIL_0001]"; `text` contains john@example.com again.
 * ```
 */

import {
  gateway,
  generateText as aiGenerateText,
  streamText as aiStreamText,
  wrapLanguageModel,
} from "ai";
import type { LanguageModel, LanguageModelMiddleware } from "ai";
import { createLlmGuard, toLanguageModelMiddleware } from "anonyma/ai";
import type { LlmGuardOptions, SanitizedMessages } from "anonyma/ai";

/** A language model object, as opposed to a model id string. */
type LanguageModelObject = Exclude<LanguageModel, string>;

/** What the model call receives, and what it returns, in the SDK's own types. */
type CallOptions = Parameters<NonNullable<LanguageModelMiddleware["transformParams"]>>[0]["params"];
type GenerateResult = Awaited<ReturnType<NonNullable<LanguageModelMiddleware["wrapGenerate"]>>>;
type StreamResult = Awaited<ReturnType<NonNullable<LanguageModelMiddleware["wrapStream"]>>>;

/** The model `wrapLanguageModel()` returns. */
export type AnonymizedLanguageModel = ReturnType<typeof wrapLanguageModel>;

/**
 * Options accepted by {@link anonymaMiddleware}, {@link withAnonyma} and
 * {@link createAnonymaAI}: what to detect and how tokens look (see
 * `LlmGuardOptions` of `anonyma/ai`), and a callback for each sanitized prompt.
 */
export interface AnonymaAIOptions extends LlmGuardOptions {
  /**
   * Called with the account of every sanitized prompt: what was replaced,
   * and above all what was passed on without inspection (`unscanned`, such
   * as images and files). Throw from it to stop a request that must not be sent.
   */
  readonly onSanitized?: (report: SanitizedMessages<unknown>) => void;
}

/**
 * Create a language-model middleware that sanitizes prompts and restores
 * tokens in responses.
 *
 * Every model call gets its own token mapping. A multi-step call
 * (`stopWhen`, tools) sends the whole conversation again at each step and
 * gets it sanitized again, so a value keeps its token as long as it first
 * appears at the same place in the conversation.
 *
 * @param options - What to detect, how tokens look, and a report callback.
 * @returns A `LanguageModelMiddleware` for `wrapLanguageModel()`.
 * @throws ValidationError (from `anonyma`) When the detection spec is invalid.
 *
 * @example
 * ```ts
 * import { wrapLanguageModel } from "ai";
 * import { anonymaMiddleware } from "@anonyma/vercel-ai";
 *
 * const model = wrapLanguageModel({ model: baseModel, middleware: anonymaMiddleware() });
 * ```
 */
export function anonymaMiddleware(options: AnonymaAIOptions = {}): LanguageModelMiddleware {
  const { onSanitized, ...guardOptions } = options;
  const adapter = toLanguageModelMiddleware(
    createLlmGuard(guardOptions),
    onSanitized !== undefined ? { onSanitized } : {},
  );

  // The adapter is typed structurally, without depending on the SDK; the
  // values it returns are the SDK's own objects with strings replaced.
  return {
    specificationVersion: "v4",
    async transformParams({ params }): Promise<CallOptions> {
      return (await adapter.transformParams({ params })) as CallOptions;
    },
    async wrapGenerate({ doGenerate, params }): Promise<GenerateResult> {
      return (await adapter.wrapGenerate({ doGenerate, params })) as GenerateResult;
    },
    async wrapStream({ doStream, params }): Promise<StreamResult> {
      return (await adapter.wrapStream({ doStream, params })) as StreamResult;
    },
  };
}

/** The provider the AI SDK resolves a model id string with. */
interface DefaultProvider {
  languageModel(modelId: string): LanguageModelObject;
}

/**
 * Resolve a model id string the way the AI SDK does: through
 * `globalThis.AI_SDK_DEFAULT_PROVIDER`, or the AI Gateway.
 */
function resolveModel(model: LanguageModel): LanguageModelObject {
  if (typeof model !== "string") return model;
  const configured = (globalThis as { AI_SDK_DEFAULT_PROVIDER?: DefaultProvider })
    .AI_SDK_DEFAULT_PROVIDER;
  return (configured ?? gateway).languageModel(model);
}

/**
 * Wrap a model so that every call through it is sanitized and restored.
 *
 * @param model - A model object, or a model id string resolved like the AI SDK does.
 * @param options - What to detect, how tokens look, and a report callback.
 * @returns The wrapped model, usable wherever the AI SDK takes a model.
 *
 * @example
 * ```ts
 * import { streamText } from "ai";
 * import { withAnonyma } from "@anonyma/vercel-ai";
 *
 * const result = streamText({ model: withAnonyma("openai/gpt-5"), prompt });
 * for await (const text of result.textStream) process.stdout.write(text);
 * ```
 */
export function withAnonyma(
  model: LanguageModel,
  options: AnonymaAIOptions = {},
): AnonymizedLanguageModel {
  return wrapLanguageModel({ model: resolveModel(model), middleware: anonymaMiddleware(options) });
}

/**
 * The AI SDK functions, with every model they are given wrapped.
 */
export interface AnonymaAI {
  /** The middleware, for `wrapLanguageModel()` or a provider registry. */
  readonly middleware: LanguageModelMiddleware;
  /** Wrap a model; see {@link withAnonyma}. */
  readonly wrap: (model: LanguageModel) => AnonymizedLanguageModel;
  /** `generateText()` of the AI SDK, with `model` wrapped. */
  readonly generateText: typeof aiGenerateText;
  /** `streamText()` of the AI SDK, with `model` wrapped. */
  readonly streamText: typeof aiStreamText;
}

/**
 * Create drop-in replacements for `generateText()` and `streamText()` that
 * sanitize every prompt and restore every response.
 *
 * @param options - What to detect, how tokens look, and a report callback.
 * @returns The functions and the middleware they share.
 *
 * @example
 * ```ts
 * import { createAnonymaAI } from "@anonyma/vercel-ai";
 *
 * const { generateText, streamText } = createAnonymaAI({ skipRoles: ["system"] });
 * const { text } = await generateText({ model, prompt: "Email john@example.com" });
 * ```
 */
export function createAnonymaAI(options: AnonymaAIOptions = {}): AnonymaAI {
  const middleware = anonymaMiddleware(options);
  const wrap = (model: LanguageModel): AnonymizedLanguageModel =>
    wrapLanguageModel({ model: resolveModel(model), middleware });

  const generateText = ((callOptions: Parameters<typeof aiGenerateText>[0]) =>
    aiGenerateText({ ...callOptions, model: wrap(callOptions.model) })) as typeof aiGenerateText;
  const streamText = ((callOptions: Parameters<typeof aiStreamText>[0]) =>
    aiStreamText({ ...callOptions, model: wrap(callOptions.model) })) as typeof aiStreamText;

  return Object.freeze({ middleware, wrap, generateText, streamText });
}
