import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createMcpServer } from "../src/mcp/index.js";
import { ANONYMA_MANIFEST } from "../src/schemas.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  version: string;
  description: string;
};

describe("version", () => {
  it("is the same in package.json and wherever the code reports it", async () => {
    const initialized = await createMcpServer().handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "t", version: "0" },
      },
    });
    expect(initialized).toMatchObject({ result: { serverInfo: { version: pkg.version } } });
    expect(ANONYMA_MANIFEST.version).toBe(pkg.version);
  });

  it("has a changelog section", () => {
    const changelog = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8");
    expect(changelog).toContain(`## [${pkg.version}]`);
  });
});
