# anonyma-wasm

wasm-bindgen bindings of [`anonyma-core`](../../crates/anonyma-core) for browsers
and edge runtimes (Cloudflare Workers, Deno, Bun): the JSON API of
[`anonyma-ffi`](../../crates/anonyma-ffi) and a vault handle.

```sh
cargo install wasm-pack
wasm-pack build bindings/wasm --target web --release
```

```js
import init, { call, Vault } from "./pkg/anonyma_wasm.js";
await init();
const { ok } = JSON.parse(
  call("detect", JSON.stringify({ text: "Mail ana@example.com", categories: ["email"], offsets: "utf-16" })),
);
```

## Status

A scaffold: CI builds it for `wasm32-unknown-unknown`; it is not published.
The TypeScript package `anonyma` already runs on every one of these runtimes
with zero dependencies and is what the site's playground uses. This binding
becomes useful when the Rust core is faster than the TypeScript engine on a
runtime that matters, or detects something the TypeScript engine does not;
the benchmark in `bench/` decides, before anything ships.

Binary size matters on the edge: the release profile uses LTO and strips
symbols; `wasm-opt -Oz` (from wasm-pack) shrinks it further. The `regex`
crate's Unicode tables are most of the size.
