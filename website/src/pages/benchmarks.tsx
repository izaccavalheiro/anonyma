import Layout from "@theme/Layout";
import type { ReactNode } from "react";
import Benchmarks from "../components/Benchmarks";
import Engines from "../components/Benchmarks/Engines";

export default function BenchmarksPage(): ReactNode {
  return (
    <Layout
      title="Benchmarks"
      description="Every engine of anonyma on one corpus, and the TypeScript engine's throughput, scaling, per-detector cost and memory."
    >
      <main className="container margin-vert--lg">
        <h1>Benchmarks</h1>
        <h2>Every engine, one corpus</h2>
        <Engines />
        <h2>The TypeScript engine</h2>
        <Benchmarks />
      </main>
    </Layout>
  );
}
