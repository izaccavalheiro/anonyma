// Package anonyma detects and anonymizes personal data in text with the Rust
// core of anonyma (crates/anonyma-core), through its C ABI (crates/anonyma-ffi).
//
// The package links a static library of the core, lib/<GOOS>_<GOARCH>/libanonyma_ffi.a,
// built for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64.
// In a clone of the repository, build it for the current platform with
//
//	go generate
//
// which needs a Rust toolchain (see buildlib.go).
//
// Offsets in [Match] are byte offsets into the Go string.
package anonyma

//go:generate go run buildlib.go

// The system libraries are those rustc prints with --print native-static-libs
// (buildlib.go shows them). On darwin, clang links libSystem by default and
// nothing in the library calls libiconv, so it needs no flag.

/*
#cgo linux,amd64 LDFLAGS: ${SRCDIR}/lib/linux_amd64/libanonyma_ffi.a
#cgo linux,arm64 LDFLAGS: ${SRCDIR}/lib/linux_arm64/libanonyma_ffi.a
#cgo darwin,amd64 LDFLAGS: ${SRCDIR}/lib/darwin_amd64/libanonyma_ffi.a
#cgo darwin,arm64 LDFLAGS: ${SRCDIR}/lib/darwin_arm64/libanonyma_ffi.a
#cgo windows,amd64 LDFLAGS: ${SRCDIR}/lib/windows_amd64/libanonyma_ffi.a
#cgo linux LDFLAGS: -lm -lrt -lpthread -lutil -ldl
#cgo windows LDFLAGS: -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -lsynchronization
#include <string.h>
#include "anonyma.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// Error is an error reported by the Rust core.
type Error struct{ Message string }

func (e *Error) Error() string { return "anonyma: " + e.Message }

// ErrClosed is returned by the methods of a closed [Vault].
var ErrClosed = errors.New("anonyma: vault is closed")

// decode reads an answer of the JSON API, `{"ok": …}` or `{"error": "…"}`, in
// one pass and in place: the result goes straight into out, and the C string
// is read without a copy and freed afterwards.
func decode(raw *C.char, out any) error {
	defer C.anonyma_string_free(raw)
	answer := struct {
		OK    any     `json:"ok"`
		Error *string `json:"error"`
	}{OK: out}
	if out == nil {
		answer.OK = new(json.RawMessage)
	}
	text := unsafe.Slice((*byte)(unsafe.Pointer(raw)), C.strlen(raw))
	if err := json.Unmarshal(text, &answer); err != nil {
		return fmt.Errorf("anonyma: unreadable answer: %w", err)
	}
	if answer.Error != nil {
		return &Error{Message: *answer.Error}
	}
	return nil
}

// cPointer is the address of a NUL-terminated buffer, for the duration of a call.
func cPointer(buf []byte) *C.char {
	return (*C.char)(unsafe.Pointer(&buf[0]))
}

// call performs op on an input already encoded and NUL-terminated.
func call(op string, input []byte, out any) error {
	cop := cString(op)
	return decode(C.anonyma_call(cPointer(cop), cPointer(input)), out)
}

// Call performs an operation of the JSON API (see packages/conformance/README.md)
// and decodes its result into out.
func Call(op string, input any, out any) error {
	payload, err := marshalInput(input)
	if err != nil {
		return err
	}
	return call(op, payload, out)
}

// Rule anonymizes one category with a strategy, such as
// {"strategy": "mask", "keepTrailing": 4}.
type Rule struct {
	Category string         `json:"category"`
	Strategy map[string]any `json:"strategy"`
}

// Options selects what to detect and how to replace it.
type Options struct {
	// Categories to detect ("email", "credit-card", ...).
	Categories []string `json:"categories,omitempty"`
	// Compliance presets ("lgpd", "gdpr", "hipaa", ...).
	Presets []string `json:"preset,omitempty"`
	// A strategy per category. Without presets, the rules are the categories
	// detected; with presets, they override the presets' strategies and add
	// the categories they name.
	Rules []Rule `json:"rules,omitempty"`
	// Use the aggressive detectors.
	Aggressive bool `json:"aggressive,omitempty"`
	// Verify check digits where the default detector does not (CPF).
	Strict bool `json:"strict,omitempty"`
	// Accept categories the core does not detect in full yet.
	AllowPartial bool `json:"allowPartial,omitempty"`
}

// fields encodes the options once, as members to splice into each call's input.
func (o Options) fields() ([]byte, error) {
	return optionFields(o)
}

// Match is a value of personal data found in a text. Start and End are byte offsets.
type Match struct {
	Category   string  `json:"category"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}

// Detect finds every value of personal data in text, without overlaps, in document order.
func Detect(text string, opts Options) ([]Match, error) {
	fields, err := opts.fields()
	if err != nil {
		return nil, err
	}
	var out struct {
		Matches []Match `json:"matches"`
	}
	if err := call("detect", textInput(text, fields), &out); err != nil {
		return nil, err
	}
	return out.Matches, nil
}

// Anonymize replaces every value found with its category's strategy.
func Anonymize(text string, opts Options) (string, error) {
	fields, err := opts.fields()
	if err != nil {
		return "", err
	}
	return anonymize(text, fields)
}

// anonymize is [Anonymize] with the options already encoded, for callers that
// make many calls with one set of options.
func anonymize(text string, fields []byte) (string, error) {
	var out struct {
		Text string `json:"text"`
	}
	if err := call("anonymize", textInput(text, fields), &out); err != nil {
		return "", err
	}
	return out.Text, nil
}

// Validate runs a checksum validator ("luhn", "cpf", "cnpj", "iban", ...).
func Validate(validator, value string) (bool, error) {
	var out struct {
		Valid bool `json:"valid"`
	}
	err := Call("validate", map[string]string{"validator": validator, "value": value}, &out)
	return out.Valid, err
}

// Vault holds the tokens of one conversation and the original values they
// stand for. It is safe for concurrent use. Close it when the conversation ends.
type Vault struct {
	mu  sync.Mutex
	ptr *C.AnonymaVault
}

// NewVault returns an empty vault.
func NewVault() *Vault {
	v := &Vault{ptr: C.anonyma_vault_new()}
	runtime.SetFinalizer(v, (*Vault).Close)
	return v
}

// Close frees the vault and every value it holds.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ptr != nil {
		C.anonyma_vault_free(v.ptr)
		v.ptr = nil
	}
	return nil
}

func (v *Vault) call(op string, input []byte, out any) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ptr == nil {
		return ErrClosed
	}
	cop := cString(op)
	return decode(C.anonyma_vault_call(v.ptr, cPointer(cop), cPointer(input)), out)
}

// Shield replaces personal data with vault tokens ({{EMAIL_1}}) before a
// prompt leaves for a model.
func (v *Vault) Shield(text string, opts Options) (string, error) {
	fields, err := opts.fields()
	if err != nil {
		return "", err
	}
	var out struct {
		Text string `json:"text"`
	}
	if err := v.call("shield", textInput(text, fields), &out); err != nil {
		return "", err
	}
	return out.Text, nil
}

// Restore puts the original values back into a model's answer. Tokens the
// vault does not hold stay as they are.
func (v *Vault) Restore(text string) (string, error) {
	var out struct {
		Text string `json:"text"`
	}
	input, err := marshalInput(map[string]string{"text": text})
	if err != nil {
		return "", err
	}
	if err := v.call("restore", input, &out); err != nil {
		return "", err
	}
	return out.Text, nil
}
