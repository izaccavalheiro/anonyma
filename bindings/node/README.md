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

Not published, and not planned to be. The core benchmark (`bench/core.mjs`,
step 4 of docs/rfcs/0001-polyglot-core.md) measured this addon against the
TypeScript engine: at most 1.8 times faster on detection with every category
and on anonymization, slower on the span engine and on a few categories, with
a slower first call. That does not pay for a prebuilt binary per platform, so
the npm package `anonyma` keeps its TypeScript engine. CI still builds the
addon, and the benchmark runs it, so the question can be reopened.

Build locally with `npm install && npm run build` in this directory.
