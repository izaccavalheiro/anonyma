# anonyma for Go

cgo bindings of the Rust core of [anonyma](https://github.com/izaccavalheiro/anonyma)
(`crates/anonyma-core`) through its C ABI (`crates/anonyma-ffi`): detection,
anonymization, the span engine, vault tokens for LLM prompts, checksum
validators, an `io.Reader` and `net/http` middleware.

```sh
go get github.com/izaccavalheiro/anonyma-go@latest
```

```go
import anonyma "github.com/izaccavalheiro/anonyma-go"

vault := anonyma.NewVault()
defer vault.Close()
prompt, _ := vault.Shield("Mail ana@example.com", anonyma.Options{Categories: []string{"email"}})
// prompt == "Mail {{EMAIL_1}}"
answer, _ := vault.Restore(modelAnswer)
```

For many calls with the same options, build an `Engine` once. Its batch methods
take many texts in one cgo call and scan short ones together, about twice as fast
as a call per text for log lines and rows:

```go
engine, err := anonyma.NewEngine(anonyma.Options{Presets: []string{"gdpr"}})
if err != nil { /* ... */ }
defer engine.Close()
clean, err := engine.AnonymizeBatch(lines) // one result per line, in order
```

Offsets in `Match` and `Span` are byte offsets into the Go string.

## Platforms

The module carries a static library of the Rust core for each platform, so
`go get` needs no Rust toolchain, only cgo and a C compiler:

| `GOOS/GOARCH`              | Library                                        |
| -------------------------- | ---------------------------------------------- |
| linux/amd64, linux/arm64   | glibc (Alpine and other musl systems: not yet) |
| darwin/amd64, darwin/arm64 | macOS                                          |
| windows/amd64              | MinGW-w64, the `gcc` that cgo uses on Windows  |

## Development

The package is developed in
[`bindings/go`](https://github.com/izaccavalheiro/anonyma/tree/main/bindings/go) of
the anonyma repository; `github.com/izaccavalheiro/anonyma-go` receives each
release with its libraries. In a clone of anonyma, build the library for your
platform with a Rust toolchain and its `llvm-tools` component
(`rustup component add llvm-tools`):

```sh
cd bindings/go
go generate        # cargo rustc ... --crate-type staticlib, copied to lib/, bitcode stripped
go test ./...
```

For another platform, set `GOOS` and `GOARCH` and add its Rust target first
(`rustup target add x86_64-pc-windows-gnu`, for instance). `go test` also runs
the conformance suite (`conformance_test.go`) through the C ABI, and checks that
`anonyma.h` is still a copy of `crates/anonyma-ffi/include/anonyma.h`.

`go generate` removes the LLVM bitcode sections that Rust's prebuilt standard
library leaves in the archive; the linker never reads them, and cgo refuses them
since Go 1.26.11 and 1.27.4.

CI builds the library on each of the five platforms, runs the tests there, and
links a program that requires the package from its module files alone, with the
Go version of `go.mod` and with the newest Go release. A tag
`go-v<version>` releases it, with `Version` in `version.go` and a section in
`CHANGELOG.md`.

## Status

Experimental (Tier 2 in
[RFC 0001](https://github.com/izaccavalheiro/anonyma/blob/main/docs/rfcs/0001-polyglot-core.md)):
the API may change before 0.1.0. A Go service without cgo can call the sidecar
(`packages/sidecar`) over HTTP instead: the same detectors.
