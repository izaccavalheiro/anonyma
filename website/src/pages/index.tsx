import Link from "@docusaurus/Link";
import CodeBlock from "@theme/CodeBlock";
import Layout from "@theme/Layout";
import type { ReactNode } from "react";
import library from "../data/library.json";
import styles from "./index.module.css";

const FEATURES: readonly (readonly [string, ReactNode])[] = [
  [
    "Finds what matters",
    <>
      {library.categories} categories — e-mail, phones, cards, IBANs, national and tax IDs of many
      countries, health and vehicle identifiers, API keys — confirmed by check digits and context,
      so look-alikes are left alone.
    </>,
  ],
  [
    "Replaces it your way",
    <>
      Redact, mask, pseudonymize, synthesize, hash, encrypt, or tokenize reversibly — per category,
      from presets for GDPR, LGPD, HIPAA, CCPA, PCI DSS and more, alone or combined.
    </>,
  ],
  [
    "Safe for LLMs",
    <>
      Prompts leave with <code>{"{{EMAIL_1}}"}</code>, answers come back with the real values, also
      when streamed. Drop-in for the Vercel AI SDK and any MCP server.
    </>,
  ],
  [
    "Stays in your process",
    <>
      No runtime dependencies, no network, no file system. Runs on Node.js, Bun, Deno, Cloudflare
      Workers and in the browser — this site included.
    </>,
  ],
  [
    "Scales to your data",
    <>
      Compiled pipelines, streams that catch values split across chunks, and a command line that
      scrubs gigabytes of logs, CSV and JSON Lines in constant memory.
    </>,
  ],
  [
    "Leaves evidence, not data",
    <>
      Hash-chained audit records and signed receipts say what was replaced, under which policy —
      never what it was.
    </>,
  ],
];

const EXAMPLE = `import { anonymize } from "anonyma";

anonymize("Ana (ana@example.com, CPF 529.982.247-25) paid with 4111 1111 1111 1111", {
  preset: ["lgpd", "pci-dss"],
}).text;
// "Ana ([REDACTED], CPF [REDACTED]) paid with [REDACTED]"
// Combined presets: LGPD's redaction beats PCI DSS's mask for the card.`;

export default function Home(): ReactNode {
  return (
    <Layout
      title="Personal data, found and anonymized"
      description="A zero-dependency TypeScript library that finds personal data and anonymizes it — in your process, on the edge, before it reaches an LLM."
    >
      <header className={styles["hero"]}>
        <div className="container">
          <h1>Personal data, found and anonymized</h1>
          <p className={styles["tagline"]}>
            A TypeScript library with no dependencies that finds personal data in text and JSON and
            replaces it — in your process, on the edge, and before it reaches a model.
          </p>
          <div className={styles["buttons"]}>
            <Link className="button button--primary button--lg" to="/docs">
              Get started
            </Link>
            <Link className="button button--secondary button--lg" to="/playground">
              Try it in your browser
            </Link>
          </div>
          <div className={styles["install"]}>npm install anonyma</div>
          <div className={styles["facts"]}>
            <span>v{library.version}</span>
            <span>0 runtime dependencies</span>
            <span>{library.presets.length} compliance presets</span>
            <span>100% test coverage</span>
            <span>MIT</span>
          </div>
        </div>
      </header>
      <main className="container">
        <section className={styles["features"]}>
          {FEATURES.map(([title, text]) => (
            <div key={title} className={styles["feature"]}>
              <h3>{title}</h3>
              <p>{text}</p>
            </div>
          ))}
        </section>
        <section className={styles["code"]}>
          <h2>One call</h2>
          <CodeBlock language="ts">{EXAMPLE}</CodeBlock>
          <p>
            Next: the <Link to="/docs/guide/quick-start">quick start</Link>, the{" "}
            <Link to="/docs/guides/scrub-files">recipes</Link>, the{" "}
            <Link to="/benchmarks">benchmarks</Link>, or the{" "}
            <Link to="/docs/reference/api">API reference</Link>.
          </p>
        </section>
      </main>
    </Layout>
  );
}
