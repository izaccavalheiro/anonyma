import BrowserOnly from "@docusaurus/BrowserOnly";
import Layout from "@theme/Layout";
import type { ReactNode } from "react";

export default function PlaygroundPage(): ReactNode {
  return (
    <Layout
      title="Playground"
      description="Try PII detection and anonymization in your browser: nothing you type leaves the page."
    >
      <main className="container margin-vert--lg">
        <h1>Playground</h1>
        <p>
          Paste anything — a log line, an e-mail, a support ticket — and see what anonyma finds and
          how it replaces it. Choose presets (several combine), the replacement, and whether check
          digits must hold.
        </p>
        <BrowserOnly fallback={<p>Loading the playground…</p>}>
          {() => {
            // Loaded in the browser only: the output depends on the clock and on random keys.
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            const Playground = (
              require("../components/Playground") as typeof import("../components/Playground")
            ).default;
            return <Playground />;
          }}
        </BrowserOnly>
      </main>
    </Layout>
  );
}
