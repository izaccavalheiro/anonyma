import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { TokenVaultError, ValidationError } from "../../src/errors.js";
import { compilePipeline } from "../../src/engine/index.js";
import {
  createKeyRing,
  createKeyedTokenizer,
  createMemoryVault,
  createSealedTokenizer,
  restoreTokens,
  rewrapVault,
  shredKey,
} from "../../src/vault/index.js";
import type { KeyMaterial, KeyRing, TokenVault, VaultRecord } from "../../src/vault/index.js";

const raw = (fill: number): KeyMaterial => ({ kind: "raw", bytes: new Uint8Array(32).fill(fill) });
const ringOf = (namespace = "test"): Promise<KeyRing> =>
  createKeyRing({ namespace, keys: [{ id: "k1", material: raw(1) }] });

describe("vault/keyed", () => {
  describe("createKeyedTokenizer", () => {
    it("issues the same token for the same value and resolves it through the vault", async () => {
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring: await ringOf(), vault });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      expect(token).toMatch(/^\[EMAIL_k1_[0-9A-HJKMNP-TV-Z]{12}\]$/);
      expect(await tokenizer.tokenize("alice@example.com", { category: "email" })).toBe(token);
      expect(await tokenizer.tokenize("alice@example.com", { category: "name" })).not.toBe(token);
      expect(await tokenizer.tokenize("bob@example.com", { category: "email" })).not.toBe(token);
      expect(vault.size()).toBe(3);
      expect(await tokenizer.detokenize(token)).toBe("alice@example.com");
      expect(tokenizer).toMatchObject({ scheme: "keyed", reversible: true });
      expect(token.length).toBeLessThanOrEqual(tokenizer.maxTokenLength);
    });

    it("stores nothing readable in the vault", async () => {
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring: await ringOf(), vault, now: () => 5 });
      await tokenizer.tokenize("alice@example.com", { category: "email", subject: "customer-42" });
      const [record] = [...vault.list()];
      expect(Object.keys(record ?? {}).sort()).toEqual(
        ["category", "check", "createdAt", "keyId", "sealed", "subjects", "token"].sort(),
      );
      const dump = JSON.stringify(record);
      expect(dump).not.toContain("alice");
      expect(dump).not.toContain("customer-42");
      expect(record).toMatchObject({ category: "email", keyId: "k1", createdAt: 5 });
    });

    it("is deterministic across processes that share the key ring", async () => {
      const first = await ringOf();
      const second = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
        manifest: first.manifest(),
      });
      const a = await createKeyedTokenizer({ keyring: first }).tokenize("alice@example.com", {
        category: "email",
      });
      const b = await createKeyedTokenizer({ keyring: second }).tokenize("alice@example.com", {
        category: "email",
      });
      expect(a).toBe(b);
      const other = await createKeyedTokenizer({ keyring: await ringOf("other") }).tokenize(
        "alice@example.com",
        {
          category: "email",
        },
      );
      expect(other).not.toBe(a);
    });

    it("is a one-way pseudonym without a vault", async () => {
      const tokenizer = createKeyedTokenizer({ keyring: await ringOf(), idLength: 16 });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      expect(token).toMatch(/^\[EMAIL_k1_[0-9A-HJKMNP-TV-Z]{16}\]$/);
      expect(tokenizer.reversible).toBe(false);
      expect(await tokenizer.detokenize(token)).toBe(undefined);
      expect(await tokenizer.forgetToken(token)).toBe(false);
      expect((await tokenizer.forgetSubject("s")).erased).toBe(0);
    });

    it("does not resolve unknown, malformed or expired tokens", async () => {
      let clock = 1000;
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({
        keyring: await ringOf(),
        vault,
        ttlMs: 500,
        now: () => clock,
      });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      expect(await tokenizer.detokenize(token)).toBe("alice@example.com");
      expect(await tokenizer.detokenize("[EMAIL_k1_000000000000]")).toBe(undefined);
      expect(await tokenizer.detokenize("[EMAIL_0001]")).toBe(undefined);
      expect(await tokenizer.detokenize(1 as unknown as string)).toBe(undefined);
      clock = 1500;
      expect(await tokenizer.detokenize(token)).toBe(undefined);
    });

    it("does not resolve a record whose sealed value was moved to another token", async () => {
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring: await ringOf(), vault });
      const a = await tokenizer.tokenize("alice@example.com", { category: "email" });
      const b = await tokenizer.tokenize("bob@example.com", { category: "email" });
      const recordA = vault.get(a) as VaultRecord;
      const recordB = vault.get(b) as VaultRecord;
      for (const sealed of [recordA.sealed, "!!not-base64!!", "AAAA"]) {
        expect(vault.replace({ ...recordB, sealed }, vault.get(b) as VaultRecord)).toBe(true);
        expect(await tokenizer.detokenize(b)).toBe(undefined);
      }
    });

    it("detects an identifier collision instead of returning the wrong value", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      const record = vault.get(token) as VaultRecord;
      vault.replace({ ...record, check: "someone-else" }, record);
      await expect(tokenizer.tokenize("alice@example.com", { category: "email" })).rejects.toThrow(
        TokenVaultError,
      );

      // The same check applies when another writer wins the race between get() and putIfAbsent().
      const racing: TokenVault = {
        ...vault,
        get: () => undefined,
        putIfAbsent: (candidate) => ({ ...candidate, check: "someone-else" }),
      };
      await expect(
        createKeyedTokenizer({ keyring, vault: racing }).tokenize("bob@example.com", {
          category: "email",
        }),
      ).rejects.toThrow(/collision/);
    });

    it("erases by token and by data subject, and returns a receipt without personal data", async () => {
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring: await ringOf(), vault, now: () => 42 });
      const mail = await tokenizer.tokenize("alice@example.com", {
        category: "email",
        subject: "customer-42",
      });
      const phone = await tokenizer.tokenize("555-867-5309", {
        category: "phone",
        subject: "customer-42",
      });
      const other = await tokenizer.tokenize("bob@example.com", {
        category: "email",
        subject: "customer-7",
      });
      const loose = await tokenizer.tokenize("carol@example.com", { category: "email" });

      const receipt = await tokenizer.forgetSubject("customer-42");
      expect(receipt).toMatchObject({
        method: "vault-delete",
        erased: 2,
        keyIds: ["k1"],
        completedAt: 42,
      });
      expect(JSON.stringify(receipt)).not.toContain("customer-42");
      expect(await tokenizer.detokenize(mail)).toBe(undefined);
      expect(await tokenizer.detokenize(phone)).toBe(undefined);
      expect(await tokenizer.detokenize(other)).toBe("bob@example.com");
      expect((await tokenizer.forgetSubject("customer-42")).erased).toBe(0);

      expect(await tokenizer.forgetToken(loose)).toBe(true);
      expect(await tokenizer.forgetToken(loose)).toBe(false);
      expect(await tokenizer.detokenize(loose)).toBe(undefined);
      await expect(tokenizer.forgetSubject("")).rejects.toThrow(ValidationError);
    });

    it("rejects invalid options and values", async () => {
      const keyring = await ringOf();
      for (const idLength of [7, 27, 12.5]) {
        expect(() => createKeyedTokenizer({ keyring, idLength })).toThrow(ValidationError);
      }
      expect(() => createKeyedTokenizer({ keyring, idKeyId: "bad id" })).toThrow(ValidationError);
      expect(() => createKeyedTokenizer({ keyring, ttlMs: 0 })).toThrow(ValidationError);
      await expect(
        createKeyedTokenizer({ keyring }).tokenize(1 as unknown as string, { category: "email" }),
      ).rejects.toThrow(ValidationError);
    });

    it("works as the tokenize strategy of a pipeline and restores through restoreTokens", async () => {
      const tokenization = createKeyedTokenizer({
        keyring: await ringOf(),
        vault: createMemoryVault(),
      });
      const pipeline = compilePipeline(
        { defaultStrategy: { strategy: "tokenize" } },
        { tokenization },
      );
      const text = "Mail alice@example.com from 203.0.113.57, again alice@example.com";
      const out = (await pipeline.transformAsync(text)).text;
      expect(out).not.toContain("alice");
      expect(out.match(tokenization.tokenPattern)).toHaveLength(3);
      const restored = await restoreTokens(`${out} [EMAIL_k1_000000000000]`, tokenization);
      expect(restored).toEqual({
        text: `${text} [EMAIL_k1_000000000000]`,
        restored: 3,
        unresolved: ["[EMAIL_k1_000000000000]"],
      });
      expect(() => pipeline.transform(text)).toThrow(/asynchronous/);
    });
  });

  describe("key rotation", () => {
    it("keeps old tokens resolvable, re-seals the vault, and survives destruction of the old key", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault });
      const before = await tokenizer.tokenize("alice@example.com", {
        category: "email",
        subject: "customer-42",
      });

      await keyring.rotate({ id: "k2", material: raw(2) });
      const after = await tokenizer.tokenize("alice@example.com", { category: "email" });
      expect(after).toMatch(/^\[EMAIL_k2_/);
      expect(await tokenizer.detokenize(before)).toBe("alice@example.com");

      expect(await rewrapVault(vault, keyring)).toEqual({
        rewrapped: 1,
        current: 1,
        unrecoverable: 0,
        skipped: 0,
      });
      expect(await rewrapVault(vault, keyring)).toEqual({
        rewrapped: 0,
        current: 2,
        unrecoverable: 0,
        skipped: 0,
      });
      expect((vault.get(before) as VaultRecord).keyId).toBe("k2");

      keyring.destroy("k1");
      expect(await tokenizer.detokenize(before)).toBe("alice@example.com");
      // Erasure by subject still finds a record that was created under the destroyed version.
      expect((await tokenizer.forgetSubject("customer-42")).erased).toBe(1);
      expect(await tokenizer.detokenize(before)).toBe(undefined);
    });

    it("keeps tokens stable across rotation when the identifier key is pinned", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault, idKeyId: "k1" });
      const before = await tokenizer.tokenize("alice@example.com", { category: "email" });
      await keyring.rotate({ id: "k2", material: raw(2) });
      expect(await tokenizer.tokenize("alice@example.com", { category: "email" })).toBe(before);
      const fresh = await tokenizer.tokenize("bob@example.com", { category: "email" });
      expect(fresh).toMatch(/^\[EMAIL_k1_/);
      expect((vault.get(fresh) as VaultRecord).keyId).toBe("k2");
    });

    it("counts records it cannot re-seal and leaves them untouched", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault });
      const a = await tokenizer.tokenize("alice@example.com", { category: "email" });
      const b = await tokenizer.tokenize("bob@example.com", { category: "email", subject: "s" });
      const c = await tokenizer.tokenize("carol@example.com", { category: "email" });
      await keyring.rotate({ id: "k2", material: raw(2) });
      const recordA = vault.get(a) as VaultRecord;
      const recordB = vault.get(b) as VaultRecord;
      vault.replace({ ...recordA, sealed: "AAAA" }, recordA);
      const [subject] = recordB.subjects ?? [];
      vault.replace(
        { ...recordB, subjects: [{ tag: subject?.tag ?? "", sealed: "AAAA" }] },
        recordB,
      );
      expect(await rewrapVault(vault, keyring)).toEqual({
        rewrapped: 1,
        current: 0,
        unrecoverable: 2,
        skipped: 0,
      });
      expect(await tokenizer.detokenize(c)).toBe("carol@example.com");

      await keyring.rotate({ id: "k3", material: raw(3) });
      keyring.destroy("k1");
      expect(await rewrapVault(vault, keyring)).toEqual({
        rewrapped: 1,
        current: 0,
        unrecoverable: 2,
        skipped: 0,
      });
    });

    it("crypto-shreds a key version: its records are gone and cannot be recovered from a copy", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault });
      const old = await tokenizer.tokenize("alice@example.com", { category: "email" });
      const backup = createMemoryVault(vault.list());
      await keyring.rotate({ id: "k2", material: raw(2) });
      const kept = await tokenizer.tokenize("bob@example.com", { category: "email" });

      await expect(shredKey(keyring, "k2", vault)).rejects.toThrow(/rotate first/);
      const receipt = await shredKey(keyring, "k1", vault, () => 7);
      expect(receipt).toEqual({
        method: "crypto-shred",
        erased: 1,
        keyIds: ["k1"],
        completedAt: 7,
      });
      expect(await tokenizer.detokenize(old)).toBe(undefined);
      expect(await tokenizer.detokenize(kept)).toBe("bob@example.com");
      // Even with the old records restored from a backup, the values stay unrecoverable.
      const fromBackup = createKeyedTokenizer({ keyring, vault: backup });
      expect(await fromBackup.detokenize(old)).toBe(undefined);
      expect((await shredKey(keyring, "k1")).erased).toBe(0);
    });
  });

  describe("createMemoryVault", () => {
    it("implements insert-if-absent, replace, delete and enumeration on frozen copies", () => {
      const record: VaultRecord = {
        token: "[T]",
        category: "c",
        keyId: "k1",
        sealed: "x",
        createdAt: 1,
      };
      const vault = createMemoryVault([record]);
      expect(vault.get("[T]")).toEqual(record);
      expect(vault.get("[T]")).not.toBe(record);
      expect(Object.isFrozen(vault.get("[T]"))).toBe(true);
      expect(vault.putIfAbsent({ ...record, sealed: "y" }).sealed).toBe("x");
      expect(vault.putIfAbsent({ ...record, token: "[U]" }).token).toBe("[U]");
      expect(vault.replace({ ...record, sealed: "z" }, record)).toBe(true);
      expect(vault.get("[T]")?.sealed).toBe("z");
      // A replace is conditional on the record still being the expected one, and never creates.
      expect(vault.replace({ ...record, sealed: "w" }, record)).toBe(false);
      expect(vault.replace({ ...record, token: "[V]" }, { ...record, token: "[V]" })).toBe(false);
      expect(vault.get("[T]")?.sealed).toBe("z");
      expect(vault.get("[V]")).toBe(undefined);
      expect([...vault.list()].map((r) => r.token)).toEqual(["[T]", "[U]"]);
      expect(vault.delete("[T]")).toBe(true);
      expect(vault.delete("[T]")).toBe(false);
      expect(vault.size()).toBe(1);
    });
  });
});

describe("vault/sealed", () => {
  describe("createSealedTokenizer", () => {
    it("round-trips without any stored state and is deterministic", async () => {
      const keyring = await ringOf();
      const tokenizer = createSealedTokenizer({ keyring });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      expect(token).toMatch(/^\[EMAIL_k1\.[A-Za-z0-9_-]+\]$/);
      expect(await tokenizer.tokenize("alice@example.com", { category: "email" })).toBe(token);
      expect(token).not.toContain("alice");
      expect(token.length).toBeLessThanOrEqual(tokenizer.maxTokenLength);
      expect(tokenizer).toMatchObject({ scheme: "sealed", reversible: true });

      // A second process with the same key ring restores it.
      const elsewhere = createSealedTokenizer({
        keyring: await createKeyRing({
          namespace: "test",
          keys: [{ id: "k1", material: raw(1) }],
          manifest: keyring.manifest(),
        }),
      });
      expect(await elsewhere.detokenize(token)).toBe("alice@example.com");
      expect(`a ${token} b`.match(tokenizer.tokenPattern)).toEqual([token]);
      expect(tokenizer.partialTokenPattern?.test(`a ${token.slice(0, 20)}`)).toBe(true);
    });

    it("gives different tokens to equal values of different categories", async () => {
      const tokenizer = createSealedTokenizer({ keyring: await ringOf() });
      const a = await tokenizer.tokenize("12345", { category: "medical-record" });
      const b = await tokenizer.tokenize("12345", { category: "case-number" });
      expect(a.slice(a.indexOf("."))).not.toBe(b.slice(b.indexOf(".")));
    });

    it("rejects tokens that were altered, relabelled or sealed under another key", async () => {
      const keyring = await ringOf();
      const tokenizer = createSealedTokenizer({ keyring });
      const token = await tokenizer.tokenize("123-45-6789", { category: "ssn" });
      const flipped = token.slice(0, -3) + (token.at(-3) === "A" ? "B" : "A") + token.slice(-2);
      expect(await tokenizer.detokenize(flipped)).toBe(undefined);
      expect(await tokenizer.detokenize(token.replace("[SSN_", "[EMAIL_"))).toBe(undefined);
      expect(await tokenizer.detokenize(token.replace("_k1.", "_k9."))).toBe(undefined);
      expect(await tokenizer.detokenize("[SSN_0001]")).toBe(undefined);
      expect(await tokenizer.detokenize(42 as unknown as string)).toBe(undefined);
      const stranger = createSealedTokenizer({ keyring: await ringOf("other") });
      expect(await stranger.detokenize(token)).toBe(undefined);
    });

    it("keeps old tokens readable after rotation until the old key is destroyed", async () => {
      const keyring = await ringOf();
      const tokenizer = createSealedTokenizer({ keyring });
      const old = await tokenizer.tokenize("alice@example.com", { category: "email" });
      await keyring.rotate({ id: "k2", material: raw(2) });
      expect(await tokenizer.tokenize("alice@example.com", { category: "email" })).toMatch(
        /^\[EMAIL_k2\./,
      );
      expect(await tokenizer.detokenize(old)).toBe("alice@example.com");
      keyring.destroy("k1");
      expect(await tokenizer.detokenize(old)).toBe(undefined);
    });

    it("refuses values beyond the configured size and invalid options", async () => {
      const keyring = await ringOf();
      const tokenizer = createSealedTokenizer({ keyring, maxValueBytes: 8 });
      await expect(tokenizer.tokenize("123456789", { category: "x" })).rejects.toThrow(
        ValidationError,
      );
      await expect(
        tokenizer.tokenize("\u00e9\u00e9\u00e9\u00e9\u00e9", { category: "x" }),
      ).rejects.toThrow(ValidationError);
      await expect(tokenizer.tokenize(1 as unknown as string, { category: "x" })).rejects.toThrow(
        ValidationError,
      );
      expect(() => createSealedTokenizer({ keyring, maxValueBytes: 0 })).toThrow(ValidationError);
    });
  });

  it("round-trips any string through every reversible provider", async () => {
    const keyring = await ringOf();
    const sealed = createSealedTokenizer({ keyring, maxValueBytes: 4096 });
    const keyed = createKeyedTokenizer({ keyring, vault: createMemoryVault() });
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(fc.string({ maxLength: 60 }), fc.string({ unit: "grapheme", maxLength: 30 })),
        fc.constantFrom("email", "name", "custom thing", "x"),
        async (value, category) => {
          // Lone surrogates cannot be represented in UTF-8; they are outside the contract.
          fc.pre(value === Buffer.from(value, "utf8").toString("utf8"));
          for (const provider of [sealed, keyed]) {
            const token = await provider.tokenize(value, { category });
            expect(`${token}`.match(provider.tokenPattern)).toEqual([token]);
            expect(await provider.detokenize(token)).toBe(value);
          }
        },
      ),
      { numRuns: 150 },
    );
  });
});

describe("vault/keyed", () => {
  describe("createKeyedTokenizer", () => {
    it("renews the record of a value that is tokenized again after it expired", async () => {
      let clock = 1000;
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({
        keyring: await ringOf(),
        vault,
        ttlMs: 1000,
        now: () => clock,
      });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      expect(await tokenizer.detokenize(token)).toBe("alice@example.com");
      clock = 60_000;
      expect(await tokenizer.detokenize(token)).toBe(undefined);
      expect(await tokenizer.tokenize("alice@example.com", { category: "email" })).toBe(token);
      expect(await tokenizer.detokenize(token)).toBe("alice@example.com");
      expect(vault.get(token)).toMatchObject({ createdAt: 60_000, expiresAt: 61_000 });
      expect(vault.size()).toBe(1);
    });

    it("erases a value for every subject it was tokenized for", async () => {
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring: await ringOf(), vault });
      const phone = { category: "phone" };
      const shared = await tokenizer.tokenize("+1 415 555 0100", { ...phone, subject: "user-A" });
      expect(await tokenizer.tokenize("+1 415 555 0100", { ...phone, subject: "user-B" })).toBe(
        shared,
      );
      await tokenizer.tokenize("+1 415 555 0100", { ...phone, subject: "user-B" });
      expect(vault.get(shared)?.subjects).toHaveLength(2);
      expect(await tokenizer.forgetSubject("user-B")).toMatchObject({ erased: 1, keyIds: ["k1"] });
      expect(await tokenizer.detokenize(shared)).toBe(undefined);

      // First seen by a job that knows no subject, later tokenized for one.
      const email = await tokenizer.tokenize("carol@example.com", { category: "email" });
      expect(vault.get(email)?.subjects).toBe(undefined);
      await tokenizer.tokenize("carol@example.com", { category: "email", subject: "user-C" });
      expect((await tokenizer.forgetSubject("user-C")).erased).toBe(1);
      expect(await tokenizer.detokenize(email)).toBe(undefined);
      expect(vault.size()).toBe(0);
    });

    it("binds the lifetime of a record to its sealed value", async () => {
      let clock = 1000;
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({
        keyring: await ringOf(),
        vault,
        ttlMs: 1000,
        now: () => clock,
      });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      const record = vault.get(token) as VaultRecord;
      clock = 5000;
      // A store that drops or extends the expiry does not bring the value back.
      const { expiresAt: _dropped, ...withoutExpiry } = record;
      vault.replace(withoutExpiry, record);
      expect(await tokenizer.detokenize(token)).toBe(undefined);
      vault.replace({ ...record, expiresAt: 9_000_000 }, vault.get(token) as VaultRecord);
      expect(await tokenizer.detokenize(token)).toBe(undefined);
    });

    it("decides by unsealing when a stored record has no check value", async () => {
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring: await ringOf(), vault });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      const record = vault.get(token) as VaultRecord;
      const { check: _check, ...withoutCheck } = record;
      vault.replace(withoutCheck, record);
      expect(await tokenizer.tokenize("alice@example.com", { category: "email" })).toBe(token);

      const other = await tokenizer.tokenize("bob@example.com", { category: "email" });
      const otherRecord = vault.get(other) as VaultRecord;
      // The record of another value under this token: a collision, reported as one.
      vault.replace({ ...withoutCheck, token: other }, otherRecord);
      await expect(tokenizer.tokenize("bob@example.com", { category: "email" })).rejects.toThrow(
        TokenVaultError,
      );
    });

    it("renews a record whose sealing key was destroyed", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault, idKeyId: "k1" });
      const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
      const { check: _check, ...withoutCheck } = vault.get(token) as VaultRecord;
      vault.replace(withoutCheck, vault.get(token) as VaultRecord);
      await keyring.rotate({ id: "k2", material: raw(2) });
      await keyring.rotate({ id: "k3", material: raw(3) });
      // The record was sealed under k1; pretend it was sealed under k2, then destroy k2.
      vault.replace({ ...withoutCheck, keyId: "k2" }, vault.get(token) as VaultRecord);
      keyring.destroy("k2");
      expect(await tokenizer.detokenize(token)).toBe(undefined);
      expect(await tokenizer.tokenize("alice@example.com", { category: "email" })).toBe(token);
      expect(await tokenizer.detokenize(token)).toBe("alice@example.com");
      expect(vault.get(token)?.keyId).toBe("k3");
    });

    it("looks again when another writer renews an expired record first", async () => {
      let clock = 1000;
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const options = { keyring, ttlMs: 1000, now: (): number => clock };
      const token = await createKeyedTokenizer({ ...options, vault }).tokenize(
        "alice@example.com",
        { category: "email" },
      );
      clock = 60_000;
      // The first conditional write loses the race; the second attempt finds the record as it is then.
      let attempts = 0;
      const racing: TokenVault = {
        ...vault,
        replace: (record, expected) => (attempts++ === 0 ? false : vault.replace(record, expected)),
      };
      const tokenizer = createKeyedTokenizer({ ...options, vault: racing });
      expect(await tokenizer.tokenize("alice@example.com", { category: "email" })).toBe(token);
      expect(attempts).toBe(2);
      expect(await tokenizer.detokenize(token)).toBe("alice@example.com");
    });

    it("gives up when the record keeps changing under it", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault });
      await tokenizer.tokenize("alice@example.com", { category: "email" });
      const contended: TokenVault = { ...vault, replace: () => false };
      await expect(
        createKeyedTokenizer({ keyring, vault: contended }).tokenize("alice@example.com", {
          category: "email",
          subject: "user-A",
        }),
      ).rejects.toThrow(/kept changing/);
    });

    it("round-trips values that UTF-8 cannot represent, and a leading byte order mark", async () => {
      const keyring = await ringOf();
      const keyed = createKeyedTokenizer({ keyring, vault: createMemoryVault() });
      const sealed = createSealedTokenizer({ keyring });
      const values = ["\ufeffalice@example.com", "user-\ud83d", "user-\ud83e", "\udc00x"];
      for (const provider of [keyed, sealed]) {
        const tokens = new Set<string>();
        for (const value of values) {
          const token = await provider.tokenize(value, { category: "email" });
          tokens.add(token);
          expect(await provider.detokenize(token), JSON.stringify(value)).toBe(value);
        }
        expect(tokens.size).toBe(values.length);
      }
    });
  });

  describe("key rotation", () => {
    it("never brings back a record that is erased while the vault is being re-sealed", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault });
      const tokens: string[] = [];
      for (let i = 0; i < 50; i++) {
        tokens.push(
          await tokenizer.tokenize(`user${String(i)}@example.com`, {
            category: "email",
            subject: "user-42",
          }),
        );
      }
      await keyring.rotate({ id: "k2", material: raw(2) });
      const [rewrap, receipt] = await Promise.all([
        rewrapVault(vault, keyring),
        tokenizer.forgetSubject("user-42"),
      ]);
      expect(receipt.erased).toBe(50);
      expect(rewrap.rewrapped + rewrap.skipped).toBe(50);
      expect(rewrap.skipped).toBeGreaterThan(0);
      expect(vault.size()).toBe(0);
      for (const token of tokens) expect(await tokenizer.detokenize(token)).toBe(undefined);
    });

    it("re-tags every subject of a record under the new key version", async () => {
      const keyring = await ringOf();
      const vault = createMemoryVault();
      const tokenizer = createKeyedTokenizer({ keyring, vault, idKeyId: "k1" });
      const token = await tokenizer.tokenize("+1 415 555 0100", {
        category: "phone",
        subject: "a",
      });
      await tokenizer.tokenize("+1 415 555 0100", { category: "phone", subject: "b" });
      await keyring.rotate({ id: "k2", material: raw(2) });
      expect(await rewrapVault(vault, keyring)).toMatchObject({ rewrapped: 1, skipped: 0 });
      expect(vault.get(token)).toMatchObject({ keyId: "k2" });
      expect(vault.get(token)?.subjects).toHaveLength(2);
      expect(await tokenizer.detokenize(token)).toBe("+1 415 555 0100");
      expect((await tokenizer.forgetSubject("b")).erased).toBe(1);
    });
  });
});

describe("vault/sealed", () => {
  describe("createSealedTokenizer", () => {
    it("resolves no token whose last character was altered", async () => {
      const tokenizer = createSealedTokenizer({ keyring: await ringOf() });
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      for (const value of ["a", "abc", "alice@example.com"]) {
        const token = await tokenizer.tokenize(value, { category: "email" });
        const last = token.charAt(token.length - 2);
        for (const other of alphabet) {
          if (other === last) continue;
          const altered = `${token.slice(0, -2)}${other}]`;
          expect(await tokenizer.detokenize(altered), altered).toBe(undefined);
        }
      }
    });
  });
});
