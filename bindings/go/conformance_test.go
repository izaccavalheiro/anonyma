package anonyma

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

type conformanceCase struct {
	ID       string                     `json:"id"`
	Op       string                     `json:"op"`
	Requires []string                   `json:"requires"`
	Input    map[string]any             `json:"input"`
	Expected map[string]json.RawMessage `json:"expected"`
}

func sortedPairs(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		raw, _ := json.Marshal(item)
		out = append(out, string(raw))
	}
	sort.Strings(out)
	return out
}

func decodeAny(raw json.RawMessage) any {
	var value any
	_ = json.Unmarshal(raw, &value)
	return value
}

func compareCase(c conformanceCase, actual map[string]any) []string {
	var problems []string
	switch {
	case c.Op == "detect" || c.Op == "scan":
		list := "matches"
		if c.Op == "scan" {
			list = "spans"
		}
		want, _ := decodeAny(c.Expected[list]).([]any)
		got, _ := actual[list].([]any)
		if len(want) != len(got) {
			return []string{fmt.Sprintf("expected %d matches, got %v", len(want), got)}
		}
		for i := range want {
			w, g := want[i].(map[string]any), got[i].(map[string]any)
			for _, key := range []string{"category", "detector", "value", "start", "end", "residual"} {
				if _, ok := w[key]; ok && !reflect.DeepEqual(w[key], g[key]) {
					problems = append(problems, fmt.Sprintf("match %d %s: expected %v, got %v", i, key, w[key], g[key]))
				}
			}
			if math.Abs(w["confidence"].(float64)-g["confidence"].(float64)) > 1e-9 {
				problems = append(problems, fmt.Sprintf("match %d confidence", i))
			}
		}
	case c.Op == "anonymize" && c.Expected["textPattern"] != nil:
		pattern := regexp.MustCompile(decodeAny(c.Expected["textPattern"]).(string))
		if text, _ := actual["text"].(string); !pattern.MatchString(text) {
			problems = append(problems, "text does not match "+pattern.String())
		}
	case c.Op == "receipt.issue":
		want, _ := decodeAny(c.Expected["receipt"]).(map[string]any)
		got, _ := actual["receipt"].(map[string]any)
		for key, value := range want {
			if !reflect.DeepEqual(value, got[key]) {
				problems = append(problems, "receipt."+key)
			}
		}
		if actual["verified"] != true {
			problems = append(problems, "the issued receipt does not verify")
		}
	default:
		for key, raw := range c.Expected {
			want, got := decodeAny(raw), actual[key]
			if key == "mapping" || key == "vault" {
				if !reflect.DeepEqual(sortedPairs(want), sortedPairs(got)) {
					problems = append(problems, key)
				}
			} else if !reflect.DeepEqual(want, got) {
				problems = append(problems, fmt.Sprintf("%s: expected %v, got %v", key, want, got))
			}
		}
	}
	return problems
}

// TestConformance runs the conformance suite through the C ABI.
func TestConformance(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "packages", "conformance", "conformance-tests.json"))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("the suite is in the repository, not in the module")
	}
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Cases []conformanceCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	var caps struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := Call("capabilities", map[string]any{}, &caps); err != nil {
		t.Fatal(err)
	}
	provided := map[string]bool{}
	for _, capability := range caps.Capabilities {
		provided[capability] = true
	}

	ran := 0
	for _, c := range suite.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			for _, required := range c.Requires {
				if !provided[required] {
					t.Skipf("needs %s", required)
				}
			}
			ran++
			var actual map[string]any
			if err := Call(c.Op, c.Input, &actual); err != nil {
				t.Fatal(err)
			}
			if problems := compareCase(c, actual); len(problems) > 0 {
				t.Fatalf("%v", problems)
			}
		})
	}
	if ran < 90 {
		t.Fatalf("only %d cases ran", ran)
	}
}

// TestHeaderMatchesCore checks that anonyma.h, which the package compiles
// against, is a copy of the header of the C ABI.
func TestHeaderMatchesCore(t *testing.T) {
	core, err := os.ReadFile(filepath.Join("..", "..", "crates", "anonyma-ffi", "include", "anonyma.h"))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("the core is in the repository, not in the module")
	}
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile("anonyma.h")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(normalize(core), normalize(copied)) {
		t.Fatal("anonyma.h differs from crates/anonyma-ffi/include/anonyma.h: copy it again")
	}
}

// normalize drops carriage returns, which a Windows checkout may add.
func normalize(text []byte) []byte { return bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n")) }
