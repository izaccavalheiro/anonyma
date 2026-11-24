# anonyma-native

[anonyma](https://github.com/izaccavalheiro/anonyma)'s detection and anonymization on its Rust core,
for Node.js. An engine is built once from options, returns what anonyma returns, and runs batches on
every core.

```sh
npm install anonyma-native
```

```js
import { createEngine } from "anonyma-native";

const engine = createEngine({ preset: "gdpr" });
engine.anonymize("Mail ana@example.com"); // { text: "Mail id_965a0cc59dce9271", matches: [] }
engine.detect("Card 4111 1111 1111 1111"); // [{ category: "credit-card", start: 5, end: 24, ... }]
engine.anonymizeBatch(lines); // [{ index, ok, value }, ...] as anonymizeBatch()
engine.close();
```

`gdpr` pseudonymizes emails: the id differs on every run, as in anonyma.

- **The same results as anonyma.** Matches have anonyma's shape, with offsets in UTF-16 code units;
  batch entries are those of `detectBatch()` and `anonymizeBatch()`. A test compares both on the
  benchmark corpus.
- **Options:** `preset` (a name or a list), `rules`, `defaultStrategy`, `categories`, `aggressive`,
  `strict`. Options the core does not run (custom detectors and patterns, allowlists, plugins,
  consistent tokens, a global replacement) throw a `NativeOptionsError`: use anonyma for those.
- **Platforms:** prebuilt for Linux (x64, arm64, glibc), macOS (x64, arm64) and Windows (x64),
  installed as an optional dependency. Elsewhere, including Alpine (musl), Cloudflare Workers and
  browsers, use anonyma, whose TypeScript engine runs everywhere.
- **Calls are synchronous.** A batch spreads over every core but blocks the calling thread until
  it ends; for a server, keep batches to a size your latency allows.

## How fast

Against anonyma 1.5 on a 4-core laptop (Intel Core i5-8265U, Windows 11, Node.js 26), synthetic
text with one value per 200 characters:

| Call                                    | anonyma | anonyma-native | Speed-up |
| --------------------------------------- | ------: | -------------: | -------: |
| `detect`, 1 KB                          | 0.36 ms |        0.12 ms |    2.9× |
| `detect`, 1 MB                          |  276 ms |         116 ms |    2.4× |
| `anonymize` with `gdpr`, 1 MB           |  294 ms |         117 ms |    2.5× |
| `detectBatch`, 10,000 lines of 200 B    |  579 ms |          82 ms |    7.0× |
| `anonymizeBatch` with `gdpr`, 10,000    |  538 ms |          74 ms |    7.3× |

The span engine (`anonyma/engine`, `scan`) and detection with only a few categories stay faster in
anonyma, which this package does not replace.

## Also

`call(op, json)` and `Vault` expose the core's JSON API, as the other bindings do.

## Building

`npm run build` here builds the addon with cargo and puts it next to the package, where it is
loaded before any prebuilt one; `npm test` compares it with the root build of anonyma.
