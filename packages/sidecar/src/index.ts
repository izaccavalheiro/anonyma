/**
 * @module anonyma-sidecar
 * @description A local HTTP and MCP service that scrubs personal data for
 * applications in any language. See README.md for the endpoints.
 */

export { createSidecar } from "./server.js";
export type { Sidecar, SidecarOptions } from "./server.js";
export { SessionStore } from "./sessions.js";
export type { Session, SessionStoreOptions } from "./sessions.js";
