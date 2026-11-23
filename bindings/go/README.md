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

The package links a static library of the Rust core, `lib/<GOOS>_<GOARCH>/libanonyma_ffi.a`,
for linux/amd64, linux/arm64 (glibc), darwin/amd64, darwin/arm64 and windows/amd64
(MinGW-w64, the `gcc` cgo uses on Windows). In a clone of the repository, build it
for your platform with a Rust toolchain:

```sh
cd bindings/go
go generate        # cargo rustc ... --crate-type staticlib, copied to lib/
go test ./...
```

For another platform, set `GOOS` and `GOARCH`; `buildlib.go` adds no Rust target
for you (`rustup target add x86_64-pc-windows-gnu`, for instance). `go test` also
runs the conformance suite (`conformance_test.go`) through the C ABI, and checks
that `anonyma.h` is still a copy of `crates/anonyma-ffi/include/anonyma.h`.

CI builds the library on each of the five platforms, runs the tests there, and
links a program that requires the package from its module files alone.

## Status

Experimental (Tier 2 in docs/rfcs/0001-polyglot-core.md). `go get` alone does
not work yet: the libraries are built and tested per platform, but no release
publishes them in a module version yet. Until one does, build the library as
above, or call the sidecar (`packages/sidecar`) over HTTP: the same detectors,
no cgo. Alpine and other musl systems are not among the platforms.
