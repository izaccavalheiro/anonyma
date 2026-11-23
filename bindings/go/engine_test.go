package anonyma

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

// batchTexts mixes values at the edges of texts, labels at their ends,
// multi-byte characters and a NUL byte (synthetic values only).
func batchTexts() []string {
	texts := []string{"", "no data", "José: jose@example.com", "a\x00ana@example.com", "Dear Ana Example"}
	for i := 0; i < 300; i++ {
		texts = append(texts,
			fmt.Sprintf("see Passport:%s", []string{"", " ", "\n"}[i%3]),
			fmt.Sprintf("A1234567 user%d@example.com card 4111 1111 1111 1111", i),
			entry(i),
		)
	}
	return texts
}

func TestEngineDetectsAsTheFunctionsDo(t *testing.T) {
	engine, err := NewEngine(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for _, text := range []string{"José: jose@example.com", "Card 4111111111111111"} {
		got, err := engine.Detect(text)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := Detect(text, Options{})
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: got %+v, want %+v", text, got, want)
		}
		anonymized, err := engine.Anonymize(text)
		wanted, _ := Anonymize(text, Options{})
		if err != nil || anonymized != wanted {
			t.Fatalf("%q: got %q, %v, want %q", text, anonymized, err, wanted)
		}
	}
}

func TestEngineBatchesMatchOneCallPerText(t *testing.T) {
	engine, err := NewEngine(Options{Presets: []string{"gdpr"}, Rules: []Rule{
		{Category: "email", Strategy: map[string]any{"strategy": "mask", "keepTrailing": 4}},
	}, AllowPartial: true})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	texts := batchTexts()
	matches, err := engine.DetectBatch(texts)
	if err != nil || len(matches) != len(texts) {
		t.Fatalf("got %d results, %v", len(matches), err)
	}
	for i, text := range texts {
		one, err := engine.Detect(text)
		if err != nil {
			t.Fatal(err)
		}
		if len(one) == 0 && len(matches[i]) == 0 {
			continue
		}
		if !reflect.DeepEqual(matches[i], one) {
			t.Fatalf("%q: batch %+v, one by one %+v", text, matches[i], one)
		}
	}
	// Deterministic strategies only: gdpr pseudonymizes without a seed, at random.
	redacting, err := NewEngine(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer redacting.Close()
	anonymized, err := redacting.AnonymizeBatch(texts)
	if err != nil || len(anonymized) != len(texts) {
		t.Fatalf("got %d results, %v", len(anonymized), err)
	}
	for i, text := range texts {
		if want, _ := redacting.Anonymize(text); anonymized[i] != want {
			t.Fatalf("%q: batch %q, one by one %q", text, anonymized[i], want)
		}
	}
	if empty, err := engine.DetectBatch(nil); err != nil || len(empty) != 0 {
		t.Fatalf("got %v, %v", empty, err)
	}
}

func TestEngineIsSafeForConcurrentUse(t *testing.T) {
	engine, err := NewEngine(emails)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				got, err := engine.DetectBatch([]string{fmt.Sprintf("u%d@example.com", g), "x"})
				if err != nil || len(got) != 2 || len(got[0]) != 1 {
					t.Errorf("got %+v, %v", got, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestEngineErrors(t *testing.T) {
	if _, err := NewEngine(Options{Categories: []string{"nope"}}); err == nil {
		t.Fatal("expected an error for an unknown category")
	}
	bad := Options{Rules: []Rule{{Category: "email", Strategy: map[string]any{"x": make(chan int)}}}}
	if _, err := NewEngine(bad); err == nil {
		t.Fatal("expected an error for options that cannot be encoded")
	}
	engine, err := NewEngine(emails)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.call("nope", textInput("x", nil), nil); err == nil {
		t.Fatal("expected an error for an unknown operation")
	}
	engine.Close()
	engine.Close()
	if _, err := engine.Detect("x"); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("got %v", err)
	}
	if _, err := engine.Anonymize("x"); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("got %v", err)
	}
	if _, err := engine.DetectBatch([]string{"x"}); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("got %v", err)
	}
	if _, err := engine.AnonymizeBatch([]string{"x"}); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("got %v", err)
	}
}
