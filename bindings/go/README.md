# anonyma for Go

cgo bindings of [`anonyma-core`](../../crates/anonyma-core) through the C ABI of
[`anonyma-ffi`](../../crates/anonyma-ffi): detection, anonymization, vault
tokens for LLM prompts, checksum validators, an `io.Reader` and `net/http`
middleware.

```go
import anonyma "github.com/izaccavalheiro/anonyma/bindings/go"

vault := anonyma.NewVault()
defer vault.Close()
prompt, _ := vault.Shield("Mail ana@example.com", anonyma.Options{Categories: []string{"email"}})
// prompt == "Mail {{EMAIL_1}}"
answer, _ := vault.Restore(modelAnswer)
```

Offsets in `Match` are byte offsets into the Go string.

## Building

The package links the static library of the Rust core. From the repository root:

```sh
cargo build --release -p anonyma-ffi   # target/release/libanonyma_ffi.a
cd bindings/go && go test ./...
```

`go test` also runs the conformance suite (`conformance_test.go`) through the C ABI.

## Status

Experimental (Tier 2 in docs/rfcs/0001-polyglot-core.md). `go get` alone does
not work yet: it needs a prebuilt `libanonyma_ffi.a` per platform, which the
release workflow does not publish yet. Until it does, a Go service can call the
sidecar (`packages/sidecar`) over HTTP: the same detectors, no cgo.
