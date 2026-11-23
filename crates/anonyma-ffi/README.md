# anonyma-ffi

The JSON API of [`anonyma-core`](../anonyma-core) (`anonyma_ffi::api::call`)
and its C ABI (`include/anonyma.h`), for the bindings that cannot pass Rust
types: Go (cgo), Node.js (napi-rs), WebAssembly, and any language with a C
foreign function interface.

The operations and their inputs are those of the conformance suite
(`packages/conformance/README.md`), plus `capabilities` and `validators`.
`tests/conformance.rs` runs the suite through this layer, which tests the core
beneath it as well.

```c
#include "anonyma.h"

char *answer = anonyma_call("detect",
    "{\"text\": \"Mail ana@example.com\", \"categories\": [\"email\"], \"offsets\": \"bytes\"}");
/* {"ok":{"matches":[{"category":"email","value":"ana@example.com","start":5,...}]}} */
anonyma_string_free(answer);
```

`detect` reports offsets in code points by default. Pass `"offsets": "utf-16"`
(JavaScript, Java, C#) or `"offsets": "bytes"` (Go, C) to get your language's unit.

Serializing every call costs a copy of the text into and out of JSON:
microseconds for a prompt, noticeable only for megabytes. The Python binding
avoids it on its hot paths by passing native strings.
