package anonyma

import (
	"fmt"
	"strings"
	"testing"
)

// entry is a synthetic log line of about 200 bytes with one email address.
func entry(i int) string {
	return fmt.Sprintf("2026-11-23T10:%02d:%02dZ INFO request %06d served for user%d@example.com "+
		"in %d ms; the cache was warm, the queue held %d items and nothing else happened.",
		i/60%60, i%60, i, i, 10+i%90, i%17)
}

// document is a synthetic text of about n bytes, one value per 200 bytes.
func document(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString(entry(i))
		b.WriteByte('\n')
	}
	return b.String()
}

func BenchmarkDetectShortEntry(b *testing.B) {
	entries := make([]string, 1000)
	for i := range entries {
		entries[i] = entry(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Detect(entries[i%len(entries)], Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDetect100KB(b *testing.B) {
	text := document(100_000)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Detect(text, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkInputEncoding measures the Go side of a call alone: the options and
// the text encoded into one input.
func BenchmarkInputEncoding(b *testing.B) {
	text := entry(7)
	opts := Options{Presets: []string{"gdpr"}, Rules: []Rule{
		{Category: "email", Strategy: map[string]any{"strategy": "redact"}},
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fields, err := opts.fields()
		if err != nil {
			b.Fatal(err)
		}
		_ = textInput(text, fields)
	}
}
