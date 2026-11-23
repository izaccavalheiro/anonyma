# anonyma-native (Node.js, Bun)

napi-rs bindings of [`anonyma-core`](../../crates/anonyma-core): the JSON API of
[`anonyma-ffi`](../../crates/anonyma-ffi) and a vault handle.

```js
const { call, Vault } = require("anonyma-native");

const vault = new Vault();
const { ok } = JSON.parse(
  vault.call("shield", JSON.stringify({ text: "Mail ana@example.com", categories: ["email"] })),
);
ok.text; // "Mail {{EMAIL_1}}"
```

Pass `"offsets": "utf-16"` to `detect` to get JavaScript string indices.

## Status

A scaffold: it builds in CI (`cargo build -p anonyma-node`) and is not
published. The TypeScript package `anonyma` keeps its own engine. The plan
(docs/rfcs/0001-polyglot-core.md, Tier 1B): once the Rust core detects every
category and passes the whole conformance suite, `anonyma` gains an opt-in
native engine behind its unchanged public API, with the TypeScript engine as
the fallback on runtimes without native modules.

Build locally with `npm install && npm run build` in this directory.
