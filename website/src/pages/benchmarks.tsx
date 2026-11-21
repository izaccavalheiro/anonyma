import Layout from "@theme/Layout";
import type { ReactNode } from "react";
import Benchmarks from "../components/Benchmarks";

export default function BenchmarksPage(): ReactNode {
  return (
    <Layout
      title="Benchmarks"
      description="Throughput, scaling, per-detector cost and memory of anonyma."
    >
      <main className="container margin-vert--lg">
        <h1>Benchmarks</h1>
        <Benchmarks />
      </main>
    </Layout>
  );
}
