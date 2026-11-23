package anonyma

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
)

// NewReader anonymizes r line by line. A value split across two lines is not
// detected; use [Anonymize] on whole documents.
func NewReader(r io.Reader, opts Options) io.Reader {
	pr, pw := io.Pipe()
	// One engine for every line: the options are parsed and the detectors built once.
	engine, err := NewEngine(opts)
	if err != nil {
		pw.CloseWithError(err)
		return pr
	}
	go func() {
		defer engine.Close()
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for scanner.Scan() {
			line, err := engine.Anonymize(scanner.Text())
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if _, err := io.WriteString(pw, line+"\n"); err != nil {
				return
			}
		}
		pw.CloseWithError(scanner.Err())
	}()
	return pr
}

// MaxBodyBytes is the largest request body [Middleware] anonymizes; a larger
// one is refused with 413, never forwarded unscrubbed.
var MaxBodyBytes int64 = 1 << 20

// Middleware anonymizes the bodies of text and JSON requests before next sees
// them. Replacements (labels, masks) contain no character JSON escapes, so a
// JSON body stays valid.
func Middleware(next http.Handler, opts Options) http.Handler {
	// One engine for every request; options it cannot be built from fail each
	// request, as Anonymize would.
	engine, engineErr := NewEngine(opts)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := r.Header.Get("Content-Type")
		if r.Body == nil || !(strings.HasPrefix(kind, "text/") || strings.Contains(kind, "json")) {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
		r.Body.Close()
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > MaxBodyBytes {
			http.Error(w, "body too large to anonymize", http.StatusRequestEntityTooLarge)
			return
		}
		if engineErr != nil {
			http.Error(w, "anonymization failed", http.StatusInternalServerError)
			return
		}
		clean, err := engine.Anonymize(string(body))
		if err != nil {
			http.Error(w, "anonymization failed", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader([]byte(clean)))
		r.ContentLength = int64(len(clean))
		r.Header.Del("Content-Length")
		next.ServeHTTP(w, r)
	})
}
