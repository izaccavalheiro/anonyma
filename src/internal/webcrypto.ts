/**
 * @module internal/webcrypto
 * @description Locates the Web Crypto API in every supported runtime.
 * @internal
 */

import { CryptoNotAvailableError } from "../errors.js";

let nodeFallback: Promise<Crypto | undefined> | undefined;

/**
 * Node.js 18 ships Web Crypto but does not expose it as a global. The module
 * specifier is held in a variable so that bundlers targeting other runtimes do
 * not try to resolve it.
 */
async function importNodeWebCrypto(): Promise<Crypto | undefined> {
  try {
    const specifier = "node:crypto";
    const mod = (await import(/* @vite-ignore */ specifier)) as { webcrypto?: Crypto };
    return mod.webcrypto;
  } catch {
    // A runtime that has neither a global crypto nor node:crypto.
    return undefined;
  }
}

/**
 * Return the Web Crypto implementation of the current runtime.
 *
 * @throws {@link CryptoNotAvailableError} When the runtime has no Web Crypto API.
 * @internal
 */
export async function webCrypto(): Promise<Crypto> {
  const globalCrypto = (globalThis as { crypto?: Crypto }).crypto;
  if (globalCrypto?.subtle !== undefined) return globalCrypto;

  nodeFallback ??= importNodeWebCrypto();
  const fallback = await nodeFallback;
  if (fallback?.subtle === undefined) throw new CryptoNotAvailableError();
  return fallback;
}
