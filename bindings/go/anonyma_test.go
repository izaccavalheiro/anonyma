package anonyma

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var emails = Options{Categories: []string{"email"}}

func TestDetectReportsByteOffsets(t *testing.T) {
	text := "José: jose@example.com"
	matches, err := Detect(text, emails)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || text[matches[0].Start:matches[0].End] != "jose@example.com" {
		t.Fatalf("unexpected matches %+v", matches)
	}
}

func TestScanReportsSpansWithByteOffsets(t *testing.T) {
	text := "José: jose@example.com"
	spans, err := Scan(text, ScanOptions{Categories: []string{"email"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 || text[spans[0].Start:spans[0].End] != "jose@example.com" ||
		spans[0].Detector == "" || spans[0].Residual {
		t.Fatalf("unexpected spans %+v", spans)
	}
	if _, err := Scan(text, ScanOptions{Detection: "nope"}); err == nil {
		t.Fatal("expected an error for an unknown detection")
	}
}

func TestVersionIsSemantic(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`).MatchString(Version) {
		t.Fatalf("Version %q", Version)
	}
}

func TestAnonymizeWithRules(t *testing.T) {
	out, err := Anonymize("Card 4111111111111111, ana@example.com", Options{Rules: []Rule{
		{Category: "credit-card", Strategy: map[string]any{"strategy": "mask", "keepTrailing": 4}},
		{Category: "email", Strategy: map[string]any{"strategy": "redact"}},
	}})
	if err != nil || out != "Card ************1111, [REDACTED]" {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestUnknownPresetsAreErrors(t *testing.T) {
	if _, err := Anonymize("x", Options{Presets: []string{"nope"}}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestVaultRoundTrip(t *testing.T) {
	vault := NewVault()
	defer vault.Close()
	shielded, err := vault.Shield("Mail ana@example.com", emails)
	if err != nil || shielded != "Mail {{EMAIL_1}}" {
		t.Fatalf("got %q, %v", shielded, err)
	}
	restored, err := vault.Restore("Sent to {{EMAIL_1}}")
	if err != nil || restored != "Sent to ana@example.com" {
		t.Fatalf("got %q, %v", restored, err)
	}
	vault.Close()
	if _, err := vault.Restore("x"); err != ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	ok, err := Validate("cpf", "529.982.247-25")
	if err != nil || !ok {
		t.Fatalf("got %v, %v", ok, err)
	}
	if _, err := Validate("nope", "1"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestReaderAndMiddleware(t *testing.T) {
	out, err := io.ReadAll(NewReader(strings.NewReader("a ana@example.com\nb\n"), emails))
	if err != nil || string(out) != "a [REDACTED]\nb\n" {
		t.Fatalf("got %q, %v", out, err)
	}

	var seen string
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = string(body)
	}), emails)
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"to":"ana@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if seen != `{"to":"[REDACTED]"}` {
		t.Fatalf("got %q", seen)
	}
}
