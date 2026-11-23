package anonyma

import (
	"encoding/json"
	"unicode/utf8"
)

// The input of a call is built in one byte buffer that ends with a NUL byte,
// and the C library reads it in place: no map of the options, no second
// encoding, no copy into C memory. cgo allows passing a pointer to Go memory
// that holds no Go pointers for the duration of a call.

const hexDigits = "0123456789abcdef"

// appendJSONString appends s as a JSON string, as encoding/json writes it:
// control characters, `"` and `\` escaped, `<`, `>`, `&`, U+2028 and U+2029 as
// \u escapes, and every byte of invalid UTF-8 as U+FFFD. A NUL byte inside s is
// escaped too, so the buffer holds no NUL before its end.
func appendJSONString(buf []byte, s string) []byte {
	buf = append(buf, '"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if b >= 0x20 && b != '"' && b != '\\' && b != '<' && b != '>' && b != '&' {
				i++
				continue
			}
			buf = append(buf, s[start:i]...)
			switch b {
			case '"', '\\':
				buf = append(buf, '\\', b)
			case '\n':
				buf = append(buf, '\\', 'n')
			case '\r':
				buf = append(buf, '\\', 'r')
			case '\t':
				buf = append(buf, '\\', 't')
			default:
				buf = append(buf, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			buf = append(buf, s[start:i]...)
			buf = append(buf, `�`...)
			i += size
			start = i
			continue
		}
		if r == ' ' || r == ' ' {
			buf = append(buf, s[start:i]...)
			buf = append(buf, '\\', 'u', '2', '0', '2', hexDigits[r&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	buf = append(buf, s[start:]...)
	return append(buf, '"')
}

// optionFields returns the members of the options' JSON object without its
// braces ("" for no options), to splice into a call's input.
func optionFields(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// encoding/json writes a struct as an object: `{` members `}`.
	return raw[1 : len(raw)-1], nil
}

// textInput builds `{"text":…,"offsets":"bytes",<fields>}` and a NUL byte.
func textInput(text string, fields []byte) []byte {
	buf := make([]byte, 0, len(text)+len(fields)+48)
	buf = append(buf, `{"text":`...)
	buf = appendJSONString(buf, text)
	buf = append(buf, `,"offsets":"bytes"`...)
	if len(fields) > 0 {
		buf = append(buf, ',')
		buf = append(buf, fields...)
	}
	return append(buf, '}', 0)
}

// cString returns s and a NUL byte, for a C string argument; s holds no NUL.
func cString(s string) []byte {
	buf := make([]byte, 0, len(s)+1)
	buf = append(buf, s...)
	return append(buf, 0)
}

// marshalInput encodes any input of the JSON API and appends a NUL byte.
func marshalInput(input any) ([]byte, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return append(payload, 0), nil
}
