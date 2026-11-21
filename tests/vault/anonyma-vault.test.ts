import { describe, expect, it } from "vitest";
import {
  InMemoryVault as RootInMemoryVault,
  detokenize,
  restore as rootRestore,
  tokenize,
  tokenizeAsync,
} from "../../src/index.js";
import { TokenVaultError, ValidationError } from "../../src/errors.js";
import { compilePipeline } from "../../src/engine/index.js";
import { createRestoreTransformer, createLlmGuard } from "../../src/ai/index.js";
import {
  InMemoryVault,
  createSessionTokenizer,
  createVaultTokenizer,
  restore,
  restoreTokens,
} from "../../src/vault/index.js";
import type { AnonymaVault } from "../../src/vault/index.js";

/** A vault that answers every call on a later microtask, like a network store. */
function asyncVault(initial: Iterable<[string, string]> = []) {
  const map = new Map<string, string>(initial);
  const calls: string[] = [];
  const vault: AnonymaVault = {
    async store(key, value) {
      calls.push(`store ${key}`);
      await Promise.resolve();
      map.set(key, value);
    },
    async retrieve(key) {
      calls.push(`retrieve ${key}`);
      await Promise.resolve();
      return map.get(key);
    },
  };
  return { vault, map, calls };
}

/** Feed `chunks` through a restore transformer and join the output. */
async function restoreStreamed(
  provider: Parameters<typeof createRestoreTransformer>[0],
  chunks: readonly string[],
) {
  const restorer = createRestoreTransformer(provider);
  let out = "";
  for (const chunk of chunks) out += await restorer.push(chunk);
  return out + (await restorer.flush());
}

describe("vault/anonyma-vault", () => {
  describe("InMemoryVault", () => {
    it("stores, retrieves, deletes and clears values", () => {
      const vault = new InMemoryVault();
      expect(vault.retrieve("{{EMAIL_1}}")).toBeUndefined();
      vault.store("{{EMAIL_1}}", "alice@example.com");
      vault.store("{{EMAIL_2}}", "bob@example.com");
      expect(vault.retrieve("{{EMAIL_1}}")).toBe("alice@example.com");
      expect(vault.size).toBe(2);
      expect(vault.entries()).toEqual([
        ["{{EMAIL_1}}", "alice@example.com"],
        ["{{EMAIL_2}}", "bob@example.com"],
      ]);
      expect(vault.delete("{{EMAIL_1}}")).toBe(true);
      expect(vault.delete("{{EMAIL_1}}")).toBe(false);
      vault.clear();
      expect(vault.size).toBe(0);
    });

    it("starts from entries and hands out copies", () => {
      const vault = new InMemoryVault([["{{PERSON_1}}", "Ada"]]);
      const entries = vault.entries();
      entries.push(["{{PERSON_2}}", "Grace"]);
      expect(vault.size).toBe(1);
      expect(new InMemoryVault(vault.entries()).retrieve("{{PERSON_1}}")).toBe("Ada");
    });

    it("rejects an empty key and a value that is not a string", () => {
      const vault = new InMemoryVault();
      expect(() => vault.store("", "x")).toThrow(ValidationError);
      expect(() => vault.store("k", 42 as unknown as string)).toThrow(ValidationError);
    });

    it("is exported from the root entry point", () => {
      expect(RootInMemoryVault).toBe(InMemoryVault);
      expect(rootRestore).toBe(restore);
    });
  });

  describe("restore", () => {
    it("never confuses {{PERSON_1}} with {{PERSON_10}}", () => {
      const vault = new InMemoryVault([
        ["{{PERSON_1}}", "Ada"],
        ["{{PERSON_10}}", "Grace"],
        ["{{PERSON_100}}", "Hedy"],
      ]);
      const result = restore("{{PERSON_10}}, {{PERSON_1}} and {{PERSON_100}}", vault);
      expect(result).toEqual({ text: "Grace, Ada and Hedy", restored: 3, unresolved: [] });
    });

    it("does not scan restored values again", () => {
      const vault = new InMemoryVault([
        ["{{NOTE_1}}", "see {{NOTE_2}}"],
        ["{{NOTE_2}}", "secret"],
      ]);
      expect(restore("{{NOTE_1}}", vault).text).toBe("see {{NOTE_2}}");
    });

    it("inserts values literally, replacement patterns included", () => {
      const vault = new InMemoryVault([["{{API_KEY_1}}", "$&$1$$"]]);
      expect(restore("key: {{API_KEY_1}}", vault).text).toBe("key: $&$1$$");
    });

    it("reports unknown tokens and leaves them in place", () => {
      const vault = new InMemoryVault([["{{EMAIL_1}}", "a@example.com"]]);
      expect(restore("{{EMAIL_1}} {{EMAIL_9}} {{EMAIL_9}}", vault)).toEqual({
        text: "a@example.com {{EMAIL_9}} {{EMAIL_9}}",
        restored: 1,
        unresolved: ["{{EMAIL_9}}", "{{EMAIL_9}}"],
      });
      expect(restore("nothing here", vault)).toEqual({
        text: "nothing here",
        restored: 0,
        unresolved: [],
      });
    });

    it("recognises every token shape anonyma issues, tags included", () => {
      const vault = new InMemoryVault([
        ["[EMAIL_0001]", "a"],
        ["<EMAIL_1>", "b"],
        ["{{EMAIL_k3Xf_1}}", "c"],
        ["{{CREDIT_CARD_2}}", "d"],
      ]);
      expect(restore("[EMAIL_0001] <EMAIL_1> {{EMAIL_k3Xf_1}} {{CREDIT_CARD_2}}", vault).text).toBe(
        "a b c d",
      );
    });

    it("accepts a custom pattern, whatever its flags", () => {
      const vault = new InMemoryVault([
        ["@@user7", "Ada"],
        ["@@user77", "Grace"],
      ]);
      expect(restore("@@user77 / @@user7", vault, { pattern: /@@user\d+/y }).text).toBe(
        "Grace / Ada",
      );
      // A pattern that matches the empty string matches nothing useful.
      expect(restore("abc", vault, { pattern: /x*/ }).text).toBe("abc");
    });

    it("treats an answer that is not a string as unknown", () => {
      const vault = {
        store: () => undefined,
        retrieve: () => null as unknown as string | undefined,
      };
      expect(restore("{{EMAIL_1}}", vault).unresolved).toEqual(["{{EMAIL_1}}"]);
    });

    it("returns a promise for an asynchronous vault and looks each token up once", async () => {
      const { vault, calls } = asyncVault([
        ["{{EMAIL_1}}", "a@example.com"],
        ["{{PHONE_1}}", "555-0100"],
      ]);
      const pending = restore("{{EMAIL_1}} {{PHONE_1}} {{EMAIL_1}} {{IPV4_1}}", vault);
      expect(pending).toBeInstanceOf(Promise);
      expect(await pending).toEqual({
        text: "a@example.com 555-0100 a@example.com {{IPV4_1}}",
        restored: 3,
        unresolved: ["{{IPV4_1}}"],
      });
      expect(calls).toEqual([
        "retrieve {{EMAIL_1}}",
        "retrieve {{PHONE_1}}",
        "retrieve {{IPV4_1}}",
      ]);
    });

    it("validates its arguments", () => {
      const vault = new InMemoryVault();
      expect(() => restore(42 as unknown as string, vault)).toThrow(ValidationError);
      expect(() => restore("x", {} as AnonymaVault)).toThrow(ValidationError);
      expect(() => restore("x", null as unknown as AnonymaVault)).toThrow(ValidationError);
      expect(() => restore("x", vault, { pattern: "x" as unknown as RegExp })).toThrow(
        ValidationError,
      );
    });

    it("stays fast on text that only looks like the start of tokens", () => {
      const vault = new InMemoryVault();
      const text = "{{A" + "_1".repeat(20_000);
      const started = performance.now();
      expect(restore(text, vault).text).toBe(text);
      expect(performance.now() - started).toBeLessThan(1_000);
    });
  });
});

describe("vault/vault-tokenizer", () => {
  describe("createVaultTokenizer", () => {
    it("issues {{CATEGORY_N}} tokens per category and stores them", () => {
      const vault = new InMemoryVault();
      const tokenizer = createVaultTokenizer({ vault });
      expect(tokenizer.tokenize("john@example.com", { category: "email" })).toBe("{{EMAIL_1}}");
      expect(tokenizer.tokenize("jane@example.com", { category: "email" })).toBe("{{EMAIL_2}}");
      expect(tokenizer.tokenize("john@example.com", { category: "email" })).toBe("{{EMAIL_1}}");
      expect(tokenizer.tokenize("Ada Lovelace", { category: "name" })).toBe("{{PERSON_1}}");
      expect(vault.entries()).toEqual([
        ["{{EMAIL_1}}", "john@example.com"],
        ["{{EMAIL_2}}", "jane@example.com"],
        ["{{PERSON_1}}", "Ada Lovelace"],
      ]);
      expect(tokenizer).toMatchObject({ scheme: "vault", reversible: true, vault });
      expect(tokenizer.detokenize("{{EMAIL_2}}")).toBe("jane@example.com");
      expect(tokenizer.detokenize("{{EMAIL_3}}")).toBeUndefined();
    });

    it("plugs into the engine and restores through restoreTokens", async () => {
      const vault = new InMemoryVault();
      const tokenization = createVaultTokenizer({ vault });
      const pipeline = compilePipeline(
        { defaultStrategy: { strategy: "tokenize" } },
        { tokenization },
      );
      const text = "Mail john@example.com, cc jane@example.com and john@example.com";
      const safe = pipeline.transform(text).text;
      expect(safe).toBe("Mail {{EMAIL_1}}, cc {{EMAIL_2}} and {{EMAIL_1}}");
      expect(tokenization.restore(safe).text).toBe(text);
      expect((await restoreTokens(safe, tokenization)).text).toBe(text);
    });

    it("continues a vault without overwriting it, and reuses tokens of known values", () => {
      const vault = new InMemoryVault();
      const first = createVaultTokenizer({ vault });
      first.tokenize("a@example.com", { category: "email" });
      first.tokenize("b@example.com", { category: "email" });

      const second = createVaultTokenizer({ vault });
      expect(second.tokenize("c@example.com", { category: "email" })).toBe("{{EMAIL_3}}");
      expect(second.tokenize("b@example.com", { category: "email" })).toBe("{{EMAIL_2}}");
      expect(vault.retrieve("{{EMAIL_1}}")).toBe("a@example.com");
      expect(vault.size).toBe(3);
    });

    it("reuses the token a synchronous vault already holds for the value", () => {
      const vault = new InMemoryVault([["{{EMAIL_1}}", "a@example.com"]]);
      const tokenizer = createVaultTokenizer({ vault });
      expect(tokenizer.tokenize("a@example.com", { category: "email" })).toBe("{{EMAIL_1}}");
      expect(vault.size).toBe(1);
    });

    it("skips a number the vault holds for another value", () => {
      const vault = new InMemoryVault([["{{EMAIL_2}}", "taken@example.com"]]);
      const tokenizer = createVaultTokenizer({ vault });
      expect(tokenizer.tokenize("a@example.com", { category: "email" })).toBe("{{EMAIL_1}}");
      expect(tokenizer.tokenize("b@example.com", { category: "email" })).toBe("{{EMAIL_3}}");
    });

    it("treats a null answer as a free number", () => {
      const map = new Map<string, string>();
      const vault = {
        store: (key: string, value: string) => void map.set(key, value),
        retrieve: (key: string) => (map.get(key) ?? null) as string | undefined,
      };
      const tokenizer = createVaultTokenizer({ vault });
      expect(tokenizer.tokenize("a@example.com", { category: "email" })).toBe("{{EMAIL_1}}");
      expect(tokenizer.detokenize("{{EMAIL_9}}")).toBeUndefined();
    });

    it("supports the other shapes, a tag, prefixes and a normalisation", () => {
      const bracket = createVaultTokenizer({ vault: new InMemoryVault(), format: "bracket" });
      expect(bracket.tokenize("a@example.com", { category: "email" })).toBe("[EMAIL_0001]");
      const angle = createVaultTokenizer({ vault: new InMemoryVault(), format: "angle" });
      expect(angle.tokenize("a@example.com", { category: "email" })).toBe("<EMAIL_1>");

      const vault = new InMemoryVault();
      const tagged = createVaultTokenizer({
        vault,
        tag: "k3Xf",
        prefixes: { email: "MAIL" },
        normalize: (value) => value.toLowerCase(),
      });
      const token = tagged.tokenize("Ada@Example.com", { category: "email" });
      expect(token).toBe("{{MAIL_k3Xf_1}}");
      expect(tagged.tokenize("ada@example.com", { category: "email" })).toBe(token);
      expect(tagged.tokenize("ACME-1", { category: "order-id" })).toBe("{{ORDER_ID_k3Xf_1}}");
      // Token-shaped text without the tag is not one of this tokenizer's tokens.
      vault.store("{{MAIL_1}}", "should not leak");
      expect(tagged.restore("{{MAIL_1}} {{MAIL_k3Xf_1}}")).toEqual({
        text: "{{MAIL_1}} Ada@Example.com",
        restored: 1,
        unresolved: [],
      });
    });

    it("works over an asynchronous vault, one allocation at a time", async () => {
      const { vault, map } = asyncVault([["{{EMAIL_1}}", "earlier@example.com"]]);
      const tokenizer = createVaultTokenizer({ vault });
      const tokens = await Promise.all([
        tokenizer.tokenize("a@example.com", { category: "email" }),
        tokenizer.tokenize("b@example.com", { category: "email" }),
        tokenizer.tokenize("a@example.com", { category: "email" }),
        tokenizer.tokenize("earlier@example.com", { category: "email" }),
        tokenizer.tokenize("203.0.113.9", { category: "ipv4" }),
      ]);
      expect(tokens).toEqual([
        "{{EMAIL_2}}",
        "{{EMAIL_3}}",
        "{{EMAIL_2}}",
        "{{EMAIL_1}}",
        "{{IPV4_1}}",
      ]);
      expect(map.size).toBe(4);
      expect(await tokenizer.detokenize("{{EMAIL_3}}")).toBe("b@example.com");
      expect(await tokenizer.detokenize("{{EMAIL_9}}")).toBeUndefined();
      expect(await tokenizer.restore("{{EMAIL_3}}!")).toMatchObject({ text: "b@example.com!" });
    });

    it("reuses the token an asynchronous vault already holds for the value", async () => {
      const { vault } = asyncVault([
        ["{{EMAIL_1}}", "a@example.com"],
        ["{{EMAIL_2}}", "b@example.com"],
      ]);
      const tokenizer = createVaultTokenizer({ vault });
      expect(await tokenizer.tokenize("b@example.com", { category: "email" })).toBe("{{EMAIL_2}}");
      expect(await tokenizer.tokenize("c@example.com", { category: "email" })).toBe("{{EMAIL_3}}");
    });

    it("goes on after a failed store", async () => {
      let failures = 1;
      const map = new Map<string, string>();
      const vault: AnonymaVault = {
        store: async (key, value) => {
          await Promise.resolve();
          if (failures-- > 0) throw new Error("unavailable");
          map.set(key, value);
        },
        retrieve: async (key) => map.get(key),
      };
      const tokenizer = createVaultTokenizer({ vault });
      const failed = tokenizer.tokenize("a@example.com", { category: "email" });
      const queued = tokenizer.tokenize("b@example.com", { category: "email" });
      await expect(failed).rejects.toThrow("unavailable");
      expect(await queued).toBe("{{EMAIL_1}}");
      expect(await tokenizer.tokenize("a@example.com", { category: "email" })).toBe("{{EMAIL_2}}");
    });

    it("stores through a synchronous retrieve and an asynchronous store", async () => {
      const map = new Map<string, string>();
      const vault: AnonymaVault = {
        store: async (key, value) => void map.set(key, value),
        retrieve: (key) => map.get(key),
      };
      const tokenizer = createVaultTokenizer({ vault });
      expect(await tokenizer.tokenize("a@example.com", { category: "email" })).toBe("{{EMAIL_1}}");
      expect(map.get("{{EMAIL_1}}")).toBe("a@example.com");
    });

    it("runs asynchronous vaults through transformAsync", async () => {
      const { vault } = asyncVault();
      const tokenization = createVaultTokenizer({ vault });
      const pipeline = compilePipeline(
        { defaultStrategy: { strategy: "tokenize" } },
        { tokenization },
      );
      const text = "Mail john@example.com about 203.0.113.9";
      const { text: safe } = await pipeline.transformAsync(text);
      expect(safe).toBe("Mail {{EMAIL_1}} about {{IPV4_1}}");
      expect((await restore(safe, vault)).text).toBe(text);
    });

    it("restores tokens split across stream chunks", async () => {
      const vault = new InMemoryVault();
      const tokenizer = createVaultTokenizer({ vault });
      tokenizer.tokenize("john@example.com", { category: "email" });
      const chunks = ["Sent to {", "{EMA", "IL_1}", "} and {", "{ not a token"];
      expect(await restoreStreamed(tokenizer, chunks)).toBe(
        "Sent to john@example.com and {{ not a token",
      );
    });

    it("gives up on an asynchronous vault that never has a free number", async () => {
      const vault: AnonymaVault = {
        store: async () => undefined,
        retrieve: async () => "someone else",
      };
      const tokenizer = createVaultTokenizer({ vault });
      await expect(tokenizer.tokenize("a@example.com", { category: "email" })).rejects.toThrow(
        TokenVaultError,
      );
    });

    it("gives up on a vault that never has a free number", () => {
      const vault = { store: () => undefined, retrieve: () => "someone else" };
      const tokenizer = createVaultTokenizer({ vault });
      expect(() => tokenizer.tokenize("a@example.com", { category: "email" })).toThrow(
        TokenVaultError,
      );
    });

    it("validates its options and arguments", () => {
      const vault = new InMemoryVault();
      expect(() => createVaultTokenizer({ vault: {} as AnonymaVault })).toThrow(ValidationError);
      expect(() => createVaultTokenizer({} as { vault: AnonymaVault })).toThrow(ValidationError);
      expect(() => createVaultTokenizer({ vault, format: "round" as "brace" })).toThrow(
        ValidationError,
      );
      expect(() => createVaultTokenizer({ vault, tag: "x" })).toThrow(ValidationError);
      expect(() => createVaultTokenizer({ vault, prefixes: { email: "mail" } })).toThrow(
        ValidationError,
      );
      const tokenizer = createVaultTokenizer({ vault });
      expect(() => tokenizer.tokenize(1 as unknown as string, { category: "email" })).toThrow(
        ValidationError,
      );
      expect(() => tokenizer.detokenize(1 as unknown as string)).toThrow(ValidationError);
    });
  });
});

describe("tokenize with a vault", () => {
  it("issues {{CATEGORY_N}} tokens in document order and stores them", () => {
    const vault = new RootInMemoryVault();
    const text = "Mail john@example.com, cc jane@example.com, again john@example.com";
    const result = tokenize(text, { vault, categories: ["email"] });
    expect(result.text).toBe("Mail {{EMAIL_1}}, cc {{EMAIL_2}}, again {{EMAIL_1}}");
    expect([...result.mapping]).toEqual([
      ["{{EMAIL_1}}", "john@example.com"],
      ["{{EMAIL_2}}", "jane@example.com"],
    ]);
    expect(result.tokens.map((token) => [token.token, token.start])).toEqual([
      ["{{EMAIL_1}}", 5],
      ["{{EMAIL_2}}", 26],
      ["{{EMAIL_1}}", 50],
    ]);
    expect(rootRestore("Replied to {{EMAIL_2}}.", vault).text).toBe("Replied to jane@example.com.");
  });

  it("keeps numbering across turns of one conversation", () => {
    const vault = new RootInMemoryVault();
    tokenize("from a@example.com", { vault });
    expect(tokenize("to b@example.com, cc a@example.com", { vault }).text).toBe(
      "to {{EMAIL_2}}, cc {{EMAIL_1}}",
    );
  });

  it("honours an explicit format, and gives the angle format for custom", () => {
    const vault = new RootInMemoryVault();
    expect(tokenize("a@example.com", { vault, format: "bracket" }).text).toBe("[EMAIL_0001]");
    expect(tokenize("b@example.com", { vault, format: "custom" }).text).toBe("<EMAIL_1>");
  });

  it("needs tokenizeAsync for a vault that fails asynchronously, without an unhandled rejection", () => {
    const vault: AnonymaVault = {
      store: () => Promise.reject(new Error("unavailable")),
      retrieve: () => Promise.reject(new Error("unavailable")),
    };
    expect(() => tokenize("a@example.com", { vault })).toThrow(/tokenizeAsync/);
  });

  it("needs tokenizeAsync for an asynchronous vault", async () => {
    const { vault } = asyncVault();
    expect(() => tokenize("a@example.com", { vault })).toThrow(/tokenizeAsync/);
    const result = await tokenizeAsync("a@example.com and b@example.com", { vault });
    expect(result.text).toBe("{{EMAIL_1}} and {{EMAIL_2}}");
    expect((await rootRestore(result.text, vault)).text).toBe("a@example.com and b@example.com");
  });

  it("returns the text unchanged when nothing is detected", () => {
    const vault = new RootInMemoryVault();
    expect(tokenize("nothing to see", { vault })).toEqual({
      text: "nothing to see",
      mapping: new Map(),
      tokens: [],
    });
  });

  it("validates the text", async () => {
    const vault = new RootInMemoryVault();
    expect(() => tokenize(1 as unknown as string, { vault })).toThrow(ValidationError);
    await expect(tokenizeAsync(1 as unknown as string, { vault })).rejects.toThrow(ValidationError);
  });
});

describe("tokenize without a vault", () => {
  it("produces and restores the brace format", () => {
    const { text, mapping } = tokenize("Mail a@example.com", { format: "brace" });
    expect(text).toBe("Mail {{EMAIL_1}}");
    expect(detokenize(text, mapping)).toEqual({
      text: "Mail a@example.com",
      replacedCount: 1,
      unresolved: [],
    });
  });

  it("restores tokens whose prefix contains a digit", () => {
    const { text, mapping } = tokenize("host 192.0.2.1");
    expect(text).toBe("host [IPV4_0001]");
    expect(detokenize(text, mapping).text).toBe("host 192.0.2.1");
  });
});

describe("session tokenizer, brace format", () => {
  it("issues, restores and snapshots {{CATEGORY_N}} tokens", () => {
    const session = createSessionTokenizer({ format: "brace" });
    expect(session.tokenize("a@example.com", { category: "email" })).toBe("{{EMAIL_1}}");
    expect(session.tokenize("b@example.com", { category: "email" })).toBe("{{EMAIL_2}}");
    expect(session.restore("{{EMAIL_2}}, [EMAIL_0001]").text).toBe("b@example.com, [EMAIL_0001]");
    const resumed = createSessionTokenizer({ snapshot: session.snapshot() });
    expect(resumed.tokenize("c@example.com", { category: "email" })).toBe("{{EMAIL_3}}");
    expect(resumed.maxTokenLength).toBe(session.maxTokenLength);
  });

  it("accepts spellings a model may produce when lenient", () => {
    const session = createSessionTokenizer({ format: "brace", lenient: true });
    session.tokenize("a@example.com", { category: "email" });
    expect(session.restore("{EMAIL_1} / {{ email_01 }} / [EMAIL_1]").text).toBe(
      "a@example.com / a@example.com / a@example.com",
    );
  });

  it("restores tokens split across stream chunks, strict and lenient", async () => {
    for (const lenient of [false, true]) {
      const session = createSessionTokenizer({ format: "brace", lenient });
      session.tokenize("a@example.com", { category: "email" });
      expect(await restoreStreamed(session, ["to {", "{EMAIL", "_1}", "}."])).toBe(
        "to a@example.com.",
      );
    }
  });

  it("drives the LLM guard", () => {
    const exchange = createLlmGuard({ session: { format: "brace" } }).begin();
    expect(exchange.sanitizeText("Mail a@example.com")).toBe("Mail {{EMAIL_1}}");
    expect(exchange.restoreText("Sent: {{EMAIL_1}}").text).toBe("Sent: a@example.com");
  });

  it("rejects an unknown format", () => {
    expect(() => createSessionTokenizer({ format: "round" as "brace" })).toThrow(ValidationError);
  });
});
