/**
 * @module mcp/definitions
 * @description Model Context Protocol declarations for anonyma: the tools,
 * resources and resource templates a server exposes, with JSON Schema
 * (draft 2020-12) for every tool input and output. The declarations are plain
 * data, so they can also be registered with any MCP server framework.
 */

import { BUILTIN_CATEGORIES } from "../engine/builtin.js";

/**
 * The subset of JSON Schema used by the declarations.
 */
export interface JsonSchema {
  readonly type?: "object" | "array" | "string" | "number" | "integer" | "boolean";
  readonly description?: string;
  readonly properties?: Readonly<Record<string, JsonSchema>>;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean;
  readonly items?: JsonSchema;
  readonly enum?: readonly string[];
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly minItems?: number;
  readonly maxItems?: number;
}

/**
 * An MCP tool declaration.
 */
export interface McpTool {
  /** Unique tool name. */
  readonly name: string;
  /** Human-readable name. */
  readonly title: string;
  /** What the tool does, written for a model. */
  readonly description: string;
  /** JSON Schema of the `arguments` object. */
  readonly inputSchema: JsonSchema & { readonly type: "object" };
  /** JSON Schema of `structuredContent` in the result. */
  readonly outputSchema: JsonSchema & { readonly type: "object" };
  /** Behaviour hints for clients. */
  readonly annotations: {
    readonly readOnlyHint: boolean;
    readonly destructiveHint: boolean;
    readonly idempotentHint: boolean;
    readonly openWorldHint: boolean;
  };
}

/**
 * An MCP resource declaration.
 */
export interface McpResource {
  readonly uri: string;
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly mimeType: "application/json";
}

/**
 * An MCP resource template declaration.
 */
export interface McpResourceTemplate {
  readonly uriTemplate: string;
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly mimeType: "application/json";
}

/** Protocol revisions the server implements, newest first. */
export const MCP_PROTOCOL_VERSIONS: readonly string[] = Object.freeze([
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
]);

const PURE = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const CATEGORY: JsonSchema = { type: "string", enum: BUILTIN_CATEGORIES };
const CATEGORIES: JsonSchema = {
  type: "array",
  description:
    "Categories to detect. Leave it out for the categories of the preset, or for all categories.",
  items: CATEGORY,
  minItems: 1,
  maxItems: BUILTIN_CATEGORIES.length,
};
const PRESET: JsonSchema = {
  type: "string",
  description: "Compliance preset that selects categories and strategies.",
  enum: ["gdpr", "lgpd", "pipeda", "hipaa", "ccpa", "pci-dss", "sox", "ferpa"],
};
const TEXT: JsonSchema = {
  type: "string",
  description: "The text to process.",
  maxLength: 1_000_000,
};
const MIN_CONFIDENCE: JsonSchema = {
  type: "number",
  description: "Ignore detections below this confidence (0 to 1).",
  minimum: 0,
  maximum: 1,
};
const FIELDS: JsonSchema = {
  type: "array",
  description: "What was replaced where. Contains no replaced text.",
  items: {
    type: "object",
    properties: {
      path: { type: "string", description: "JSON Pointer of the field; empty for plain text." },
      category: { type: "string" },
      detector: { type: "string" },
      rule: { type: "string" },
      count: { type: "integer", minimum: 0 },
    },
    required: ["path", "category", "detector", "rule", "count"],
    additionalProperties: false,
  },
};

/**
 * The strategies a model may request. Strategies that need key material or a
 * token vault are not offered through this parameter.
 */
const STRATEGY: JsonSchema = {
  type: "object",
  description:
    "How detected values are replaced. Defaults to the preset's strategy, or to redaction.",
  properties: {
    strategy: {
      type: "string",
      enum: ["redact", "mask", "pseudonymize", "generalize", "synthesize"],
    },
    label: {
      type: "string",
      description: "redact: the replacement label.",
      minLength: 1,
      maxLength: 64,
    },
    maskChar: {
      type: "string",
      description: "mask: the masking character.",
      minLength: 1,
      maxLength: 1,
    },
    keepLeading: {
      type: "integer",
      description: "mask: leading characters left visible.",
      minimum: 0,
    },
    keepTrailing: {
      type: "integer",
      description: "mask: trailing characters left visible.",
      minimum: 0,
    },
    bucketSize: {
      type: "integer",
      description: "generalize: width of the numeric range.",
      minimum: 1,
    },
  },
  required: ["strategy"],
  additionalProperties: false,
};

const DETECT: McpTool = {
  name: "anonyma_detect",
  title: "Detect personal data",
  description:
    "Find personal data (email addresses, phone numbers, government identifiers, payment cards, IP addresses and more) " +
    "in a text. Returns the position, category and confidence of every detection, never the detected text itself. " +
    "Use it to decide whether text is safe to store, log or send elsewhere.",
  inputSchema: {
    type: "object",
    properties: {
      text: TEXT,
      categories: CATEGORIES,
      preset: PRESET,
      minConfidence: MIN_CONFIDENCE,
    },
    required: ["text"],
    additionalProperties: false,
  },
  outputSchema: {
    type: "object",
    properties: {
      found: { type: "boolean" },
      count: { type: "integer", minimum: 0 },
      spans: {
        type: "array",
        items: {
          type: "object",
          properties: {
            start: { type: "integer", minimum: 0 },
            end: { type: "integer", minimum: 0 },
            category: { type: "string" },
            confidence: { type: "number", minimum: 0, maximum: 1 },
            detector: { type: "string" },
          },
          required: ["start", "end", "category", "confidence", "detector"],
          additionalProperties: false,
        },
      },
    },
    required: ["found", "count", "spans"],
    additionalProperties: false,
  },
  annotations: PURE,
};

const ANONYMIZE: McpTool = {
  name: "anonyma_anonymize",
  title: "Anonymize text or JSON",
  description:
    "Replace personal data in a text, or in every string of a JSON value, irreversibly. The structure of JSON " +
    "(keys, nesting, array lengths, non-string values) is preserved. Provide exactly one of `text` and `json`. " +
    "Use it before writing data to logs, tickets, prompts or files.",
  inputSchema: {
    type: "object",
    properties: {
      text: TEXT,
      json: {
        description:
          "A JSON object or array. Its string values, its keys and its integers of 12 or more digits are anonymized.",
      },
      preset: PRESET,
      categories: CATEGORIES,
      strategy: STRATEGY,
      minConfidence: MIN_CONFIDENCE,
    },
    additionalProperties: false,
  },
  outputSchema: {
    type: "object",
    properties: {
      text: { type: "string", description: "The anonymized text, when `text` was given." },
      json: { description: "The anonymized JSON value, when `json` was given." },
      replaced: { type: "integer", minimum: 0 },
      fields: FIELDS,
    },
    required: ["replaced", "fields"],
    additionalProperties: false,
  },
  annotations: PURE,
};

const TOKENIZE: McpTool = {
  name: "anonyma_tokenize",
  title: "Replace personal data with tokens",
  description:
    "Replace personal data in a text with placeholder tokens such as [EMAIL_0001]. Equal values get equal tokens " +
    "within a session, so the text stays meaningful. The original values stay on the server. Pass the returned " +
    "`session` to later calls to keep using the same tokens.",
  inputSchema: {
    type: "object",
    properties: {
      text: TEXT,
      session: {
        type: "string",
        description: "Session returned by an earlier call.",
        minLength: 8,
        maxLength: 64,
      },
      categories: CATEGORIES,
      preset: PRESET,
      minConfidence: MIN_CONFIDENCE,
    },
    required: ["text"],
    additionalProperties: false,
  },
  outputSchema: {
    type: "object",
    properties: {
      text: { type: "string" },
      session: { type: "string" },
      replaced: { type: "integer", minimum: 0 },
      fields: FIELDS,
    },
    required: ["text", "session", "replaced", "fields"],
    additionalProperties: false,
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

const DETOKENIZE: McpTool = {
  name: "anonyma_detokenize",
  title: "Restore tokens to original values",
  description:
    "Replace the tokens of a session with the original values. This reveals personal data to the caller and is " +
    "only available when the server operator has enabled it.",
  inputSchema: {
    type: "object",
    properties: {
      text: TEXT,
      session: {
        type: "string",
        description: "Session returned by anonyma_tokenize.",
        minLength: 8,
        maxLength: 64,
      },
    },
    required: ["text", "session"],
    additionalProperties: false,
  },
  outputSchema: {
    type: "object",
    properties: {
      text: { type: "string" },
      restored: { type: "integer", minimum: 0 },
      unresolved: { type: "array", items: { type: "string" } },
    },
    required: ["text", "restored", "unresolved"],
    additionalProperties: false,
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

const CHECK_POLICY: McpTool = {
  name: "anonyma_check_policy",
  title: "Check an anonymization policy",
  description:
    "Validate an anonyma policy document and check it against the regulations it extends (GDPR, LGPD, PIPEDA, " +
    "CCPA, HIPAA, PCI DSS). Returns every problem with a JSON Pointer and, for compliance problems, the provision " +
    "that is violated.",
  inputSchema: {
    type: "object",
    properties: { policy: { type: "object", description: "The policy document." } },
    required: ["policy"],
    additionalProperties: false,
  },
  outputSchema: {
    type: "object",
    properties: {
      valid: { type: "boolean" },
      issues: {
        type: "array",
        items: {
          type: "object",
          properties: {
            severity: { type: "string", enum: ["error", "warning"] },
            path: { type: "string" },
            code: { type: "string" },
            message: { type: "string" },
            citation: { type: "string" },
          },
          required: ["severity", "path", "code", "message"],
          additionalProperties: false,
        },
      },
    },
    required: ["valid", "issues"],
    additionalProperties: false,
  },
  annotations: PURE,
};

/**
 * Every tool declaration. `anonyma_detokenize` is only served when the server
 * operator enables it.
 *
 * @example
 * ```ts
 * import { MCP_TOOLS } from "anonyma/mcp";
 *
 * for (const tool of MCP_TOOLS) console.log(tool.name, JSON.stringify(tool.inputSchema));
 * ```
 */
export const MCP_TOOLS: readonly McpTool[] = Object.freeze([
  DETECT,
  ANONYMIZE,
  TOKENIZE,
  DETOKENIZE,
  CHECK_POLICY,
]);

/**
 * Every static resource declaration.
 *
 * @example
 * ```ts
 * import { MCP_RESOURCES } from "anonyma/mcp";
 *
 * MCP_RESOURCES.map((resource) => resource.uri);
 * // ["anonyma://categories", "anonyma://strategies", "anonyma://presets", "anonyma://audit/head"]
 * ```
 */
export const MCP_RESOURCES: readonly McpResource[] = Object.freeze([
  {
    uri: "anonyma://categories",
    name: "categories",
    title: "Detectable categories",
    description: "The categories of personal data the server can detect.",
    mimeType: "application/json",
  },
  {
    uri: "anonyma://strategies",
    name: "strategies",
    title: "Anonymization strategies",
    description: "The strategies a tool call may request, and what each does to a value.",
    mimeType: "application/json",
  },
  {
    uri: "anonyma://presets",
    name: "presets",
    title: "Compliance presets",
    description: "The compliance presets with their categories and strategies.",
    mimeType: "application/json",
  },
  {
    uri: "anonyma://audit/head",
    name: "audit-head",
    title: "Audit chain head",
    description: "Sequence number and hash of the most recent audit record of this server.",
    mimeType: "application/json",
  },
]);

/**
 * Every resource template declaration.
 *
 * @example
 * ```ts
 * import { MCP_RESOURCE_TEMPLATES } from "anonyma/mcp";
 *
 * MCP_RESOURCE_TEMPLATES[0]?.uriTemplate; // "anonyma://regulations/{id}"
 * ```
 */
export const MCP_RESOURCE_TEMPLATES: readonly McpResourceTemplate[] = Object.freeze([
  {
    uriTemplate: "anonyma://regulations/{id}",
    name: "regulation",
    title: "Regulation profile",
    description:
      "For one regulation (gdpr, lgpd, pipeda, ccpa, hipaa, pci-dss): the categories in scope with the provisions " +
      "that bring them into scope, the protection required, and the data elements that cannot be detected.",
    mimeType: "application/json",
  },
]);
