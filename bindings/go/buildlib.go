//go:build ignore

// Buildlib builds the static library of the Rust core for the platform of the
// Go toolchain and copies it to lib/<GOOS>_<GOARCH>/, where the package links
// it. Run it from bindings/go with `go generate` (or `go run buildlib.go`) in a
// clone of the repository: it needs cargo, and rustup for a target other than
// the host's. Releases ship these libraries prebuilt.
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// targets maps a Go platform to the Rust target whose static library it links.
var targets = map[string]string{
	"linux/amd64":   "x86_64-unknown-linux-gnu",
	"linux/arm64":   "aarch64-unknown-linux-gnu",
	"darwin/amd64":  "x86_64-apple-darwin",
	"darwin/arm64":  "aarch64-apple-darwin",
	"windows/amd64": "x86_64-pc-windows-gnu",
}

func main() {
	if err := build(); err != nil {
		fmt.Fprintln(os.Stderr, "buildlib:", err)
		os.Exit(1)
	}
}

func build() error {
	goos, goarch := env("GOOS", runtime.GOOS), env("GOARCH", runtime.GOARCH)
	target, ok := targets[goos+"/"+goarch]
	if !ok {
		return fmt.Errorf("no Rust target for %s/%s", goos, goarch)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return err
	}
	// Only the staticlib: building the crate's cdylib for windows-gnu would need a
	// MinGW linker, and a static library needs no linker at all.
	cargo := exec.Command("cargo", "rustc", "--release", "-p", "anonyma-ffi", "--lib",
		"--crate-type", "staticlib", "--target", target, "--", "--print", "native-static-libs")
	cargo.Dir, cargo.Stdout, cargo.Stderr = root, os.Stdout, os.Stderr
	if err := cargo.Run(); err != nil {
		return err
	}
	from := filepath.Join(root, "target", target, "release", "libanonyma_ffi.a")
	dir := filepath.Join("lib", goos+"_"+goarch)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	to := filepath.Join(dir, "libanonyma_ffi.a")
	if err := copyFile(from, to); err != nil {
		return err
	}
	fmt.Println("buildlib:", to)
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
