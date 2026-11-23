package anonyma

import (
	"encoding/json"
	"strings"
	"testing"
)

// The hand-written encoder must mean what encoding/json means for every string.
func TestAppendJSONStringDecodesAsEncodingJSON(t *testing.T) {
	cases := []string{
		"",
		"plain ascii",
		`quote " and backslash \`,
		"tab\tnewline\nreturn\r\b\f\x00\x01\x1f\x7f",
		"<script>&amp;</script>",
		"José, 日本語, 😀",
		"line and paragraph",
		"invalid \xff\xfe utf-8 \xc3",
		"truncated \xe6\x97",
		strings.Repeat("ab\"c\\", 1000),
	}
	for _, s := range cases {
		var got, want string
		if err := json.Unmarshal(appendJSONString(nil, s), &got); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		reference, _ := json.Marshal(s)
		if err := json.Unmarshal(reference, &want); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%q decoded as %q, encoding/json gives %q", s, got, want)
		}
		if strings.ContainsRune(string(appendJSONString(nil, s)), 0) {
			t.Fatalf("%q: a NUL byte in the encoding", s)
		}
	}
}

func TestTextInputSplicesTheOptions(t *testing.T) {
	fields, err := Options{Categories: []string{"email"}, Strict: true}.fields()
	if err != nil {
		t.Fatal(err)
	}
	buf := textInput("a\x00b", fields)
	if buf[len(buf)-1] != 0 {
		t.Fatal("the input does not end with a NUL byte")
	}
	var input map[string]any
	if err := json.Unmarshal(buf[:len(buf)-1], &input); err != nil {
		t.Fatal(err)
	}
	if input["text"] != "a\x00b" || input["offsets"] != "bytes" || input["strict"] != true ||
		len(input) != 4 {
		t.Fatalf("unexpected input %v", input)
	}
	empty, _ := Options{}.fields()
	if string(textInput("x", empty)) != "{\"text\":\"x\",\"offsets\":\"bytes\"}\x00" {
		t.Fatalf("unexpected input %q", textInput("x", empty))
	}
}

func TestATextWithANulByteIsDetected(t *testing.T) {
	text := "a\x00ana@example.com"
	matches, err := Detect(text, emails)
	if err != nil || len(matches) != 1 || text[matches[0].Start:matches[0].End] != "ana@example.com" {
		t.Fatalf("got %+v, %v", matches, err)
	}
}

func TestOptionsThatCannotBeEncodedAreErrors(t *testing.T) {
	bad := Options{Rules: []Rule{{Category: "email", Strategy: map[string]any{"x": make(chan int)}}}}
	if _, err := Detect("ana@example.com", bad); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := Anonymize("ana@example.com", bad); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := NewVault().Shield("ana@example.com", bad); err == nil {
		t.Fatal("expected an error")
	}
}

func TestCallWithoutAResult(t *testing.T) {
	if err := Call("validate", map[string]string{"validator": "luhn", "value": "4111111111111111"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := Call("nope", map[string]string{}, nil); err == nil {
		t.Fatal("expected an error for an unknown operation")
	}
}
