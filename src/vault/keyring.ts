/**
 * @module vault/keyring
 * @description Versioned key management: every version holds one secret from
 * which independent, purpose-bound keys are derived with HKDF-SHA-256.
 *
 * Cryptographic parameters
 * - Raw material: used directly as HKDF input keying material (at least 32 bytes).
 * - Passphrases: stretched with PBKDF2-HMAC-SHA-256 (600,000 iterations by
 *   default, never fewer than 100,000) into 32 bytes of keying material.
 * - Salt: 32 random bytes per version, used for PBKDF2 and for HKDF-Extract.
 *   It is not secret and is part of the manifest.
 * - Domain separation: the HKDF `info` is `"anonyma/v1/" + purpose + NUL +
 *   namespace`, so keys differ per purpose and per namespace.
 * - Derived keys are non-extractable `CryptoKey` objects.
 * - The manifest carries an HMAC-SHA-256 under a key of the active version.
 *   A manifest that was edited (another active version, a lower iteration
 *   count, another salt) is refused when the ring is created from it.
 */

import { KeyManagementError } from "../errors.js";
import {
  fromBase64Url,
  isWellFormed,
  randomBytes,
  toBase64Url,
  utf8,
} from "../internal/encoding.js";
import type { Bytes } from "../internal/encoding.js";
import { webCrypto } from "../internal/webcrypto.js";
import { isKeyId } from "./tokens.js";
import type {
  KeyMaterial,
  KeyPurpose,
  KeyRing,
  KeyRingManifest,
  KeyState,
  KeyVersionInfo,
} from "./types.js";

const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const MIN_PBKDF2_ITERATIONS = 100_000;
const MIN_RAW_BYTES = 32;
const SALT_BYTES = 32;
const MIN_SALT_BYTES = 16;
const STATES: ReadonlySet<unknown> = new Set(["active", "retired", "destroyed"]);

/**
 * Options accepted by {@link createKeyRing}.
 */
export interface KeyRingOptions {
  /** Domain-separation label (tenant, dataset or environment). Must not be empty. */
  readonly namespace: string;
  /**
   * The secret of every live version, oldest first. Unless a manifest says
   * otherwise, the last one is active and the others are retired.
   */
  readonly keys: readonly { readonly id: string; readonly material: KeyMaterial }[];
  /**
   * The manifest of a previous run. Supplying it makes the ring derive the
   * same keys again; versions it lists as destroyed need no entry in `keys`.
   * Every entry of `keys` must be listed in it: a new version is added with
   * {@link KeyRing.rotate}, never by passing an extra key.
   */
  readonly manifest?: KeyRingManifest;
  /** Clock used for `createdAt`. Defaults to `Date.now`. */
  readonly now?: () => number;
}

interface Version {
  readonly id: string;
  state: KeyState;
  readonly createdAt: number;
  readonly kdf: "hkdf" | "pbkdf2-hkdf";
  readonly salt: Bytes;
  readonly iterations: number | undefined;
  /** HKDF base key; `undefined` once the version is destroyed. */
  base: CryptoKey | undefined;
}

async function importBase(
  crypto: Crypto,
  id: string,
  material: KeyMaterial,
  salt: Bytes,
  iterations: number | undefined,
): Promise<CryptoKey> {
  let keyingMaterial: Bytes;
  if (material.kind === "raw") {
    if (!(material.bytes instanceof Uint8Array) || material.bytes.length < MIN_RAW_BYTES) {
      throw new KeyManagementError(
        `raw key material must be at least ${String(MIN_RAW_BYTES)} bytes`,
        id,
      );
    }
    keyingMaterial = new Uint8Array(material.bytes);
  } else {
    if (typeof material.passphrase !== "string" || material.passphrase.length === 0) {
      throw new KeyManagementError("the passphrase must not be empty", id);
    }
    const passphraseKey = await crypto.subtle.importKey(
      "raw",
      utf8(material.passphrase),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations: iterations ?? DEFAULT_PBKDF2_ITERATIONS,
      },
      passphraseKey,
      256,
    );
    keyingMaterial = new Uint8Array(bits);
  }
  return crypto.subtle.importKey("raw", keyingMaterial, "HKDF", false, ["deriveKey"]);
}

function resolveIterations(
  id: string,
  material: KeyMaterial,
  fromManifest?: number,
): number | undefined {
  if (material.kind !== "passphrase") return undefined;
  if (
    fromManifest !== undefined &&
    material.iterations !== undefined &&
    material.iterations !== fromManifest
  ) {
    throw new KeyManagementError(
      "the iteration count differs from the one this version was created with",
      id,
    );
  }
  const iterations = fromManifest ?? material.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  if (!Number.isInteger(iterations) || iterations < MIN_PBKDF2_ITERATIONS) {
    throw new KeyManagementError(
      `PBKDF2 needs at least ${String(MIN_PBKDF2_ITERATIONS)} iterations`,
      id,
    );
  }
  return iterations;
}

/**
 * Generate fresh, random key material for a new key version.
 *
 * @returns 32 random bytes wrapped as {@link KeyMaterial}.
 *
 * @example
 * ```ts
 * const ring = await createKeyRing({
 *   namespace: "prod/eu",
 *   keys: [{ id: "k1", material: await generateKeyMaterial() }],
 * });
 * ```
 */
export async function generateKeyMaterial(): Promise<KeyMaterial> {
  return { kind: "raw", bytes: randomBytes(await webCrypto(), MIN_RAW_BYTES) };
}

/**
 * Create a key ring.
 *
 * @param options - Namespace, the secret of every live version, and optionally
 *   the manifest of a previous run.
 * @returns The {@link KeyRing}.
 * @throws {@link KeyManagementError} When an identifier is malformed or repeated, material is
 *   too weak, or a live version of the manifest has no material.
 *
 * @example
 * ```ts
 * import { createKeyRing } from "anonyma/vault";
 *
 * const ring = await createKeyRing({
 *   namespace: "billing",
 *   keys: [{ id: "2026a", material: { kind: "raw", bytes: secretBytes } }],
 * });
 * saveSomewhere(JSON.stringify(ring.manifest())); // not secret
 *
 * // Later: add a version, then retire and finally destroy the old one.
 * await ring.rotate({ id: "2026b", material: { kind: "raw", bytes: newSecretBytes } });
 * ring.destroy("2026a");
 * ```
 */
export async function createKeyRing(options: KeyRingOptions): Promise<KeyRing> {
  const { namespace, keys, manifest } = options;
  const now = options.now ?? Date.now;

  if (typeof namespace !== "string" || namespace.length === 0 || !isWellFormed(namespace)) {
    throw new KeyManagementError("the namespace must be a non-empty, well-formed string");
  }

  const crypto = await webCrypto();
  const versions = new Map<string, Version>();
  const derived = new Map<string, Promise<CryptoKey>>();
  let active: string | undefined;
  /** MAC of the manifest, recomputed whenever the ring gains a version. */
  let mac = "";

  const supplied = new Map<string, KeyMaterial>();
  for (const { id, material } of keys) {
    if (!isKeyId(id)) {
      throw new KeyManagementError("key identifiers are 1-16 characters of A-Z, a-z and 0-9");
    }
    if (supplied.has(id)) throw new KeyManagementError("the identifier is used more than once", id);
    supplied.set(id, material);
  }

  if (manifest === undefined) {
    for (const [id, material] of supplied) await add(id, material);
    if (active === undefined)
      throw new KeyManagementError("a key ring needs one active key version");
    mac = await sign();
  } else {
    const infos = readManifest(manifest, namespace);
    for (const info of infos) {
      const material = supplied.get(info.id);
      supplied.delete(info.id);
      const salt = fromBase64Url(info.salt) ?? new Uint8Array(0);
      if (info.state === "destroyed") {
        versions.set(info.id, { ...info, salt, iterations: info.iterations, base: undefined });
        continue;
      }
      if (material === undefined) {
        throw new KeyManagementError("no key material was supplied for a live version", info.id);
      }
      if ((material.kind === "raw") !== (info.kdf === "hkdf")) {
        throw new KeyManagementError("the key material does not match the manifest", info.id);
      }
      const iterations = resolveIterations(info.id, material, info.iterations);
      versions.set(info.id, {
        id: info.id,
        state: info.state,
        createdAt: info.createdAt,
        kdf: info.kdf,
        salt,
        iterations,
        base: await importBase(crypto, info.id, material, salt, iterations),
      });
    }
    const [unlisted] = supplied.keys();
    if (unlisted !== undefined) {
      throw new KeyManagementError(
        "the manifest does not list this key version; add new versions with rotate()",
        unlisted,
      );
    }
    active = manifest.activeKeyId;
    const expected = fromBase64Url(typeof manifest.mac === "string" ? manifest.mac : "");
    const genuine =
      expected !== undefined &&
      (await crypto.subtle.verify("HMAC", await macKey(), expected, utf8(macInput())));
    if (!genuine) {
      throw new KeyManagementError(
        "the manifest failed authentication: it was edited, or the key material is not the one it was created with",
      );
    }
    mac = manifest.mac;
  }

  /** The key that authenticates the manifest: a key of the active version. */
  function macKey(): Promise<CryptoKey> {
    return derive(activeKeyId(), "manifest-mac");
  }

  /**
   * What the manifest MAC covers. A retired and a destroyed version count the
   * same, because destroying a version is synchronous and cannot re-sign.
   */
  function macInput(): string {
    return JSON.stringify([
      1,
      namespace,
      activeKeyId(),
      [...versions.values()].map((version) => [
        version.id,
        version.state === "active",
        version.createdAt,
        version.kdf,
        toBase64Url(version.salt),
        version.iterations ?? null,
      ]),
    ]);
  }

  async function sign(): Promise<string> {
    const signature = await crypto.subtle.sign("HMAC", await macKey(), utf8(macInput()));
    return toBase64Url(new Uint8Array(signature));
  }

  async function add(id: string, material: KeyMaterial): Promise<void> {
    const salt = randomBytes(crypto, SALT_BYTES);
    const iterations = resolveIterations(id, material);
    const base = await importBase(crypto, id, material, salt, iterations);
    const previous = active === undefined ? undefined : versions.get(active);
    if (previous !== undefined) previous.state = "retired";
    versions.set(id, {
      id,
      state: "active",
      createdAt: now(),
      kdf: material.kind === "raw" ? "hkdf" : "pbkdf2-hkdf",
      salt,
      iterations,
      base,
    });
    active = id;
  }

  function activeKeyId(): string {
    /* v8 ignore next -- construction guarantees an active version */
    if (active === undefined) throw new KeyManagementError("the key ring has no active version");
    return active;
  }

  function describe(version: Version): KeyVersionInfo {
    return Object.freeze({
      id: version.id,
      state: version.state,
      createdAt: version.createdAt,
      kdf: version.kdf,
      salt: toBase64Url(version.salt),
      ...(version.iterations !== undefined ? { iterations: version.iterations } : {}),
    });
  }

  function derive(keyId: string, purpose: KeyPurpose | "manifest-mac"): Promise<CryptoKey> {
    const version = versions.get(keyId);
    if (version === undefined) {
      return Promise.reject(
        new KeyManagementError("unknown key version", isKeyId(keyId) ? keyId : undefined),
      );
    }
    const base = version.base;
    if (base === undefined) {
      return Promise.reject(new KeyManagementError("the key version has been destroyed", keyId));
    }
    const cacheKey = `${keyId}/${purpose}`;
    let key = derived.get(cacheKey);
    if (key === undefined) {
      key = crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: version.salt,
          info: utf8(`anonyma/v1/${purpose}\0${namespace}`),
        },
        base,
        purpose === "token-seal"
          ? { name: "AES-GCM", length: 256 }
          : { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        purpose === "token-seal" ? ["encrypt", "decrypt"] : ["sign", "verify"],
      );
      derived.set(cacheKey, key);
    }
    return key;
  }

  /** Identifiers of rotations that have started but not finished. */
  const reserved = new Set<string>();
  /** Rotations run one after another, so the ring always has exactly one active version. */
  let rotations: Promise<void> = Promise.resolve();

  function rotate(version: { readonly id: string; readonly material: KeyMaterial }): Promise<void> {
    const { id, material } = version;
    if (!isKeyId(id)) {
      return Promise.reject(
        new KeyManagementError("key identifiers are 1-16 characters of A-Z, a-z and 0-9"),
      );
    }
    // Checked and reserved before the first await: two calls can never share an identifier.
    if (versions.has(id) || reserved.has(id)) {
      return Promise.reject(new KeyManagementError("the identifier is already in use", id));
    }
    reserved.add(id);
    const run = rotations.then(async () => {
      try {
        await add(id, material);
        mac = await sign();
      } finally {
        reserved.delete(id);
      }
    });
    rotations = run.catch(() => undefined);
    return run;
  }

  function destroy(keyId: string): void {
    const version = versions.get(keyId);
    if (version === undefined) {
      throw new KeyManagementError("unknown key version", isKeyId(keyId) ? keyId : undefined);
    }
    if (version.state === "active") {
      throw new KeyManagementError(
        "the active key version cannot be destroyed; rotate first",
        keyId,
      );
    }
    version.state = "destroyed";
    version.base = undefined;
    for (const cacheKey of [...derived.keys()]) {
      if (cacheKey.startsWith(`${keyId}/`)) derived.delete(cacheKey);
    }
  }

  return Object.freeze({
    activeKeyId,
    manifest: (): KeyRingManifest =>
      Object.freeze({
        v: 1 as const,
        namespace,
        activeKeyId: activeKeyId(),
        versions: Object.freeze([...versions.values()].map(describe)),
        mac,
      }),
    deriveKey: (keyId: string, purpose: KeyPurpose): Promise<CryptoKey> => derive(keyId, purpose),
    rotate,
    destroy,
  });
}

/**
 * Check the shape of a manifest and return its versions.
 *
 * @throws {@link KeyManagementError} When a member is missing or has an unexpected value.
 */
function readManifest(manifest: KeyRingManifest, namespace: string): readonly KeyVersionInfo[] {
  const malformed = new KeyManagementError("the manifest is malformed");
  const candidate: Readonly<Record<string, unknown>> = manifest as unknown as Record<
    string,
    unknown
  >;
  if (
    typeof manifest !== "object" ||
    candidate["v"] !== 1 ||
    !Array.isArray(candidate["versions"])
  ) {
    throw malformed;
  }
  if (candidate["namespace"] !== namespace) {
    throw new KeyManagementError("the manifest belongs to a different namespace");
  }

  const seen = new Set<string>();
  let activeCount = 0;
  for (const entry of candidate["versions"] as readonly unknown[]) {
    if (typeof entry !== "object" || entry === null) throw malformed;
    const info = entry as Readonly<Record<string, unknown>>;
    const { id, state, createdAt, kdf, salt, iterations } = info;
    const saltBytes = typeof salt === "string" ? fromBase64Url(salt) : undefined;
    if (
      !isKeyId(id) ||
      seen.has(id) ||
      !STATES.has(state) ||
      typeof createdAt !== "number" ||
      !Number.isFinite(createdAt) ||
      (kdf !== "hkdf" && kdf !== "pbkdf2-hkdf") ||
      saltBytes === undefined ||
      saltBytes.length < MIN_SALT_BYTES ||
      (kdf === "hkdf" ? iterations !== undefined : typeof iterations !== "number")
    ) {
      throw malformed;
    }
    seen.add(id);
    if (state === "active") {
      activeCount++;
      if (id !== candidate["activeKeyId"]) throw malformed;
    }
  }
  if (activeCount !== 1) throw malformed;
  return manifest.versions;
}
