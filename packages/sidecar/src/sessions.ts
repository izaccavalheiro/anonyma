/**
 * @module anonyma-sidecar/sessions
 * @description Token vaults of the conversations a sidecar serves, bounded in
 * number and in lifetime.
 */

import { randomUUID } from "node:crypto";

import { InMemoryVault } from "anonyma";

/** One conversation: its vault and when it expires. */
export interface Session {
  /** Unguessable identifier the client sends back to restore. */
  readonly id: string;
  /** The tokens of the conversation and the original values. */
  readonly vault: InMemoryVault;
  /** Milliseconds since 1970 after which the session is dropped. */
  expires: number;
}

/** Options of {@link SessionStore}. */
export interface SessionStoreOptions {
  /** Most sessions kept; the least recently used is dropped. Defaults to 1000. */
  readonly maxSessions?: number;
  /** Lifetime of a session after its last use, in milliseconds. Defaults to 30 minutes. */
  readonly ttlMs?: number;
  /** Clock, for tests. */
  readonly now?: () => number;
}

/**
 * Sessions by id, least recently used first. Every vault holds original
 * values in clear: a session is dropped when it expires, when the store is
 * full, or when its client deletes it.
 */
export class SessionStore {
  readonly #sessions = new Map<string, Session>();
  readonly #maxSessions: number;
  readonly #ttlMs: number;
  readonly #now: () => number;

  public constructor(options: SessionStoreOptions = {}) {
    this.#maxSessions = options.maxSessions ?? 1000;
    this.#ttlMs = options.ttlMs ?? 30 * 60 * 1000;
    this.#now = options.now ?? Date.now;
    if (!Number.isInteger(this.#maxSessions) || this.#maxSessions < 1) {
      throw new RangeError("maxSessions must be a positive integer");
    }
    if (!(this.#ttlMs > 0)) throw new RangeError("ttlMs must be positive");
  }

  /** Number of live sessions. */
  public get size(): number {
    return this.#sessions.size;
  }

  /** Drop the sessions that have expired. */
  public sweep(): void {
    const now = this.#now();
    for (const [id, session] of this.#sessions) {
      if (session.expires <= now) this.#drop(id, session);
    }
  }

  /** A new session, dropping the least recently used one when the store is full. */
  public create(): Session {
    this.sweep();
    while (this.#sessions.size >= this.#maxSessions) {
      const oldest = this.#sessions.entries().next().value;
      /* v8 ignore next -- the loop runs only while the map holds sessions */
      if (oldest === undefined) break;
      this.#drop(...oldest);
    }
    const session: Session = {
      id: randomUUID(),
      vault: new InMemoryVault(),
      expires: this.#now() + this.#ttlMs,
    };
    this.#sessions.set(session.id, session);
    return session;
  }

  /** The live session `id`, marked as just used; `undefined` if unknown or expired. */
  public get(id: string): Session | undefined {
    const session = this.#sessions.get(id);
    if (session === undefined) return undefined;
    if (session.expires <= this.#now()) {
      this.#drop(id, session);
      return undefined;
    }
    // Re-inserting moves it to the end: the most recently used.
    this.#sessions.delete(id);
    session.expires = this.#now() + this.#ttlMs;
    this.#sessions.set(id, session);
    return session;
  }

  /** Drop a session. Returns whether it existed. */
  public delete(id: string): boolean {
    const session = this.#sessions.get(id);
    if (session === undefined) return false;
    this.#drop(id, session);
    return true;
  }

  /** Drop every session. */
  public clear(): void {
    for (const [id, session] of this.#sessions) this.#drop(id, session);
  }

  #drop(id: string, session: Session): void {
    session.vault.clear();
    this.#sessions.delete(id);
  }
}
