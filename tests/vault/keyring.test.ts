import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KeyManagementError } from "../../src/errors.js";
import { createKeyRing, generateKeyMaterial } from "../../src/vault/index.js";
import type { KeyMaterial, KeyRing } from "../../src/vault/index.js";

const raw = (fill: number): KeyMaterial => ({ kind: "raw", bytes: new Uint8Array(32).fill(fill) });

async function fingerprint(ring: KeyRing, keyId: string): Promise<string> {
  const key = await ring.deriveKey(keyId, "token-id");
  const mac = await webcrypto.subtle.sign("HMAC", key, new TextEncoder().encode("probe"));
  return Buffer.from(mac).toString("hex");
}

describe("vault/keyring", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("generateKeyMaterial", () => {
    it("returns 32 fresh random bytes", async () => {
      const a = await generateKeyMaterial();
      const b = await generateKeyMaterial();
      expect(a.kind).toBe("raw");
      if (a.kind !== "raw" || b.kind !== "raw") throw new Error("unreachable");
      expect(a.bytes).toHaveLength(32);
      expect(Buffer.from(a.bytes).equals(Buffer.from(b.bytes))).toBe(false);
    });
  });

  describe("createKeyRing", () => {
    it("makes the last key active and the others retired", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [
          { id: "k1", material: raw(1) },
          { id: "k2", material: raw(2) },
        ],
        now: () => 1000,
      });
      expect(ring.activeKeyId()).toBe("k2");
      const manifest = ring.manifest();
      expect(manifest).toMatchObject({ v: 1, namespace: "test", activeKeyId: "k2" });
      expect(manifest.versions.map((v) => [v.id, v.state, v.kdf, v.createdAt])).toEqual([
        ["k1", "retired", "hkdf", 1000],
        ["k2", "active", "hkdf", 1000],
      ]);
      expect(Object.isFrozen(manifest)).toBe(true);
      expect(JSON.stringify(manifest)).not.toContain("AQEB"); // no key bytes in the manifest
    });

    it("rejects invalid input without echoing key material", async () => {
      const cases: [unknown, RegExp][] = [
        [{ namespace: "", keys: [{ id: "k1", material: raw(1) }] }, /namespace/],
        [{ namespace: "n", keys: [] }, /one active key version/],
        [{ namespace: "n", keys: [{ id: "bad id", material: raw(1) }] }, /identifiers/],
        [{ namespace: "n", keys: [{ id: "k".repeat(17), material: raw(1) }] }, /identifiers/],
        [
          {
            namespace: "n",
            keys: [
              { id: "k1", material: raw(1) },
              { id: "k1", material: raw(2) },
            ],
          },
          /more than once/,
        ],
        [
          {
            namespace: "n",
            keys: [{ id: "k1", material: { kind: "raw", bytes: new Uint8Array(16) } }],
          },
          /at least 32 bytes/,
        ],
        [
          {
            namespace: "n",
            keys: [{ id: "k1", material: { kind: "raw", bytes: "x".repeat(32) } }],
          },
          /at least 32 bytes/,
        ],
        [
          {
            namespace: "n",
            keys: [{ id: "k1", material: { kind: "passphrase", passphrase: "" } }],
          },
          /passphrase/,
        ],
        [
          {
            namespace: "n",
            keys: [
              { id: "k1", material: { kind: "passphrase", passphrase: "p", iterations: 1000 } },
            ],
          },
          /at least 100000 iterations/,
        ],
      ];
      for (const [options, message] of cases) {
        await expect(createKeyRing(options as Parameters<typeof createKeyRing>[0])).rejects.toThrow(
          message,
        );
        await expect(
          createKeyRing(options as Parameters<typeof createKeyRing>[0]),
        ).rejects.toBeInstanceOf(KeyManagementError);
      }
    });

    it("derives independent, non-extractable keys per purpose and caches them", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      const idKey = await ring.deriveKey("k1", "token-id");
      const sealKey = await ring.deriveKey("k1", "token-seal");
      expect(idKey.algorithm.name).toBe("HMAC");
      expect(sealKey.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
      expect(idKey.extractable).toBe(false);
      expect(sealKey.extractable).toBe(false);
      expect(await ring.deriveKey("k1", "token-id")).toBe(idKey);

      const sign = async (purpose: "token-id" | "subject-tag" | "audit-mac"): Promise<string> =>
        Buffer.from(
          await webcrypto.subtle.sign(
            "HMAC",
            await ring.deriveKey("k1", purpose),
            new Uint8Array(4),
          ),
        ).toString("hex");
      expect(
        new Set([await sign("token-id"), await sign("subject-tag"), await sign("audit-mac")]).size,
      ).toBe(3);
    });

    it("separates namespaces and salts: equal material gives different keys", async () => {
      const a = await createKeyRing({
        namespace: "tenant-a",
        keys: [{ id: "k1", material: raw(1) }],
      });
      const b = await createKeyRing({
        namespace: "tenant-b",
        keys: [{ id: "k1", material: raw(1) }],
      });
      const a2 = await createKeyRing({
        namespace: "tenant-a",
        keys: [{ id: "k1", material: raw(1) }],
      });
      expect(await fingerprint(a, "k1")).not.toBe(await fingerprint(b, "k1"));
      expect(await fingerprint(a, "k1")).not.toBe(await fingerprint(a2, "k1")); // fresh random salt
    });

    it("derives the same keys again from the manifest and the material", async () => {
      const first = await createKeyRing({
        namespace: "test",
        keys: [
          { id: "k1", material: raw(1) },
          { id: "k2", material: raw(2) },
        ],
      });
      const manifest = JSON.parse(JSON.stringify(first.manifest())) as ReturnType<
        KeyRing["manifest"]
      >;
      const second = await createKeyRing({
        namespace: "test",
        keys: [
          { id: "k2", material: raw(2) },
          { id: "k1", material: raw(1) },
        ],
        manifest,
      });
      expect(second.activeKeyId()).toBe("k2");
      expect(await fingerprint(second, "k1")).toBe(await fingerprint(first, "k1"));
      expect(await fingerprint(second, "k2")).toBe(await fingerprint(first, "k2"));
      expect(second.manifest()).toEqual(first.manifest());
    });

    it("refuses a key that the manifest does not list", async () => {
      const first = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      // A manifest saved before a rotation: accepting k2 would give it a new salt and other keys.
      await expect(
        createKeyRing({
          namespace: "test",
          keys: [
            { id: "k1", material: raw(1) },
            { id: "k2", material: raw(2) },
          ],
          manifest: first.manifest(),
        }),
      ).rejects.toThrow(/does not list this key version/);
    });

    it("rejects a manifest that does not fit", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      const manifest = ring.manifest();
      const [version] = manifest.versions;
      if (version === undefined) throw new Error("unreachable");
      await expect(
        createKeyRing({ namespace: "other", keys: [{ id: "k1", material: raw(1) }], manifest }),
      ).rejects.toThrow(/different namespace/);
      await expect(createKeyRing({ namespace: "test", keys: [], manifest })).rejects.toThrow(
        /no key material/,
      );
      await expect(
        createKeyRing({
          namespace: "test",
          keys: [{ id: "k1", material: { kind: "passphrase", passphrase: "p" } }],
          manifest,
        }),
      ).rejects.toThrow(/does not match the manifest/);
      for (const broken of [
        { ...version, salt: "not base64!" },
        { ...version, id: "bad id" },
      ]) {
        await expect(
          createKeyRing({
            namespace: "test",
            keys: [{ id: "k1", material: raw(1) }],
            manifest: { ...manifest, versions: [broken] },
          }),
        ).rejects.toThrow(/malformed/);
      }
      await expect(
        createKeyRing({
          namespace: "test",
          keys: [{ id: "k1", material: raw(1) }],
          manifest: { ...manifest, versions: [version, version] },
        }),
      ).rejects.toThrow(/malformed/);
      await expect(
        createKeyRing({
          namespace: "test",
          keys: [{ id: "k1", material: raw(1) }],
          manifest: { ...manifest, activeKeyId: "k9" },
        }),
      ).rejects.toThrow(/malformed/);
    });

    it("stretches passphrases with PBKDF2 and records the parameters", async () => {
      const material: KeyMaterial = {
        kind: "passphrase",
        passphrase: "correct horse",
        iterations: 100_000,
      };
      const first = await createKeyRing({ namespace: "test", keys: [{ id: "p1", material }] });
      const [info] = first.manifest().versions;
      expect(info).toMatchObject({ kdf: "pbkdf2-hkdf", iterations: 100_000 });
      const second = await createKeyRing({
        namespace: "test",
        keys: [{ id: "p1", material: { kind: "passphrase", passphrase: "correct horse" } }],
        manifest: first.manifest(),
      });
      expect(await fingerprint(second, "p1")).toBe(await fingerprint(first, "p1"));
      // Another passphrase derives other keys, so the manifest no longer authenticates.
      await expect(
        createKeyRing({
          namespace: "test",
          keys: [{ id: "p1", material: { kind: "passphrase", passphrase: "wrong horse" } }],
          manifest: first.manifest(),
        }),
      ).rejects.toThrow(/failed authentication/);
    });

    it("refuses a manifest that was edited", async () => {
      const material: KeyMaterial = {
        kind: "passphrase",
        passphrase: "correct horse",
        iterations: 200_000,
      };
      const ring = await createKeyRing({
        namespace: "test",
        keys: [
          { id: "k1", material: raw(1) },
          { id: "p2", material },
        ],
      });
      const manifest = ring.manifest();
      const [k1, p2] = manifest.versions;
      if (k1 === undefined || p2 === undefined) throw new Error("unreachable");
      const keys = [
        { id: "k1", material: raw(1) },
        { id: "p2", material },
      ];
      const load = (edited: unknown): Promise<KeyRing> =>
        createKeyRing({ namespace: "test", keys, manifest: edited as typeof manifest });

      expect(manifest.mac).toMatch(/^[A-Za-z0-9_-]{43}$/);
      await expect(load(manifest)).resolves.toBeDefined();

      // Fewer iterations than the caller configured, or than the ring was created with.
      await expect(
        load({ ...manifest, versions: [k1, { ...p2, iterations: 100_000 }] }),
      ).rejects.toThrow(/iteration count differs/);
      await expect(
        createKeyRing({
          namespace: "test",
          keys: [
            { id: "k1", material: raw(1) },
            { id: "p2", material: { kind: "passphrase", passphrase: "correct horse" } },
          ],
          manifest: { ...manifest, versions: [k1, { ...p2, iterations: 100_000 }] },
        }),
      ).rejects.toThrow(/failed authentication/);

      // A retired version made active again.
      await expect(
        load({
          ...manifest,
          activeKeyId: "k1",
          versions: [
            { ...k1, state: "active" },
            { ...p2, state: "retired" },
          ],
        }),
      ).rejects.toThrow(/failed authentication/);

      const malformed: unknown[] = [
        { ...manifest, versions: [{ ...k1, state: "active" }, p2] },
        { ...manifest, versions: [{ ...k1, state: "bogus" }, p2] },
        { ...manifest, versions: [{ ...k1, salt: "" }, p2] },
        { ...manifest, versions: [{ ...k1, salt: "AA" }, p2] },
        { ...manifest, versions: [{ ...k1, salt: 7 }, p2] },
        { ...manifest, versions: [k1, { ...p2, state: "retired" }] },
        { ...manifest, versions: [{ ...k1, kdf: "bogus-kdf" }, p2] },
        { ...manifest, versions: [{ ...k1, iterations: 100_000 }, p2] },
        { ...manifest, versions: [{ ...k1, createdAt: "today" }, p2] },
        { ...manifest, versions: [k1, { ...p2, iterations: undefined }] },
        { ...manifest, versions: [null, p2] },
        { ...manifest, versions: undefined },
        { ...manifest, v: 99 },
      ];
      for (const edited of malformed) {
        await expect(load(edited), JSON.stringify(edited)).rejects.toThrow(/malformed/);
      }
      for (const mac of [undefined, "", "AAAA", `${manifest.mac.slice(0, -2)}AA`]) {
        await expect(load({ ...manifest, mac }), String(mac)).rejects.toThrow(
          /failed authentication/,
        );
      }
      // The salt of a version that still has its key is covered too.
      await expect(load({ ...manifest, versions: [{ ...k1, salt: p2.salt }, p2] })).rejects.toThrow(
        /failed authentication/,
      );
    });

    it("refuses a namespace with a lone surrogate", async () => {
      await expect(
        createKeyRing({ namespace: "tenant-\ud800", keys: [{ id: "k1", material: raw(1) }] }),
      ).rejects.toThrow(KeyManagementError);
    });

    it("works when the runtime does not expose crypto as a global (Node.js 18)", async () => {
      vi.stubGlobal("crypto", undefined);
      const ring = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      const key = await ring.deriveKey("k1", "token-id");
      expect(key.algorithm.name).toBe("HMAC");
    });
  });

  describe("rotate", () => {
    it("adds an active version and retires the previous one", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      const before = await fingerprint(ring, "k1");
      await ring.rotate({ id: "k2", material: raw(2) });
      expect(ring.activeKeyId()).toBe("k2");
      expect(ring.manifest().versions.map((v) => [v.id, v.state])).toEqual([
        ["k1", "retired"],
        ["k2", "active"],
      ]);
      expect(await fingerprint(ring, "k1")).toBe(before);
      expect(await fingerprint(ring, "k2")).not.toBe(before);
    });

    it("rejects a reused or malformed identifier", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      await expect(ring.rotate({ id: "k1", material: raw(2) })).rejects.toThrow(/already in use/);
      await expect(ring.rotate({ id: "k 2", material: raw(2) })).rejects.toThrow(/identifiers/);
      await expect(
        ring.rotate({ id: "k2", material: { kind: "raw", bytes: new Uint8Array(8) } }),
      ).rejects.toThrow(/at least 32 bytes/);
      expect(ring.activeKeyId()).toBe("k1");
    });
  });

  describe("rotate (concurrent calls)", () => {
    it("lets only one of two overlapping calls use an identifier", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      const results = await Promise.allSettled([
        ring.rotate({ id: "k2", material: raw(2) }),
        ring.rotate({ id: "k2", material: raw(3) }),
        ring.rotate({ id: "k3", material: raw(4) }),
      ]);
      expect(results.map((result) => result.status)).toEqual([
        "fulfilled",
        "rejected",
        "fulfilled",
      ]);
      expect(ring.manifest().versions.map((v) => [v.id, v.state])).toEqual([
        ["k1", "retired"],
        ["k2", "retired"],
        ["k3", "active"],
      ]);
      // The ring holds the first secret, and its manifest loads with it.
      const reloaded = await createKeyRing({
        namespace: "test",
        keys: [
          { id: "k1", material: raw(1) },
          { id: "k2", material: raw(2) },
          { id: "k3", material: raw(4) },
        ],
        manifest: ring.manifest(),
      });
      expect(await fingerprint(reloaded, "k2")).toBe(await fingerprint(ring, "k2"));
      // A failed rotation releases its identifier.
      await expect(
        ring.rotate({ id: "k4", material: { kind: "raw", bytes: new Uint8Array(4) } }),
      ).rejects.toThrow(KeyManagementError);
      await expect(ring.rotate({ id: "k4", material: raw(5) })).resolves.toBe(undefined);
    });

    it("keeps a manifest valid after a version is destroyed", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      await ring.rotate({ id: "k2", material: raw(2) });
      ring.destroy("k1");
      const reloaded = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k2", material: raw(2) }],
        manifest: ring.manifest(),
      });
      expect(reloaded.manifest()).toEqual(ring.manifest());
      await expect(reloaded.deriveKey("k1", "token-seal")).rejects.toThrow(/destroyed/);
    });
  });

  describe("destroy", () => {
    it("discards a retired version for good", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [
          { id: "k1", material: raw(1) },
          { id: "k2", material: raw(2) },
        ],
      });
      await ring.deriveKey("k1", "token-id");
      ring.destroy("k1");
      ring.destroy("k1"); // idempotent
      expect(ring.manifest().versions.map((v) => [v.id, v.state])).toEqual([
        ["k1", "destroyed"],
        ["k2", "active"],
      ]);
      await expect(ring.deriveKey("k1", "token-id")).rejects.toThrow(/destroyed/);
      await expect(ring.deriveKey("k1", "token-id")).rejects.toMatchObject({ keyId: "k1" });

      // A ring rebuilt from the manifest keeps the version destroyed and needs no material for it.
      const rebuilt = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k2", material: raw(2) }],
        manifest: ring.manifest(),
      });
      await expect(rebuilt.deriveKey("k1", "token-seal")).rejects.toThrow(/destroyed/);
      expect(await fingerprint(rebuilt, "k2")).toBe(await fingerprint(ring, "k2"));
    });

    it("refuses to destroy the active version or an unknown one", async () => {
      const ring = await createKeyRing({
        namespace: "test",
        keys: [{ id: "k1", material: raw(1) }],
      });
      expect(() => ring.destroy("k1")).toThrow(/rotate first/);
      expect(() => ring.destroy("k9")).toThrow(/unknown key version/);
      expect(() => ring.destroy("not an id")).toThrow(KeyManagementError);
      await expect(ring.deriveKey("k9", "token-id")).rejects.toThrow(/unknown key version/);
      await expect(ring.deriveKey("not an id", "token-id")).rejects.toMatchObject({
        keyId: undefined,
      });
    });
  });
});
