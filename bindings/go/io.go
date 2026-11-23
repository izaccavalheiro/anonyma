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
//
// Lines are anonymized in batches ([Engine.AnonymizeBatch]): every complete
// line already read from r, up to 4,096 lines or 1 MiB. A batch is cut as soon
// as no complete line is waiting, so an interactive stream gets each line back
// without waiting for the next. Lines end at "\n" (a "\r" before it is
// dropped) and are written back with "\n"; a line over 16 MiB is an error.
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
		pw.CloseWithError(anonymizeLines(bufio.NewReaderSize(r, 64*1024), engine, pw))
	}()
	return pr
}

// The limits of a batch of [NewReader], and of one line.
var (
	batchLines   = 4096
	batchBytes   = 1 << 20
	maxLineBytes = 16 << 20
)

func anonymizeLines(in *bufio.Reader, engine *Engine, out io.Writer) error {
	var lines []string
	size := 0
	flush := func() error {
		if len(lines) == 0 {
			return nil
		}
		clean, err := engine.AnonymizeBatch(lines)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		for _, line := range clean {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
		lines, size = lines[:0], 0
		_, err = out.Write(buf.Bytes())
		return err
	}
	for {
		line, err := readLine(in)
		if err == io.EOF {
			return flush()
		}
		if err != nil {
			// The lines before it are written, as they were one by one.
			if flushErr := flush(); flushErr != nil {
				return flushErr
			}
			return err
		}
		lines = append(lines, line)
		size += len(line)
		if len(lines) >= batchLines || size >= batchBytes || !lineWaiting(in) {
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

// lineWaiting reports whether a complete line is already buffered, so that
// reading it does not wait on r.
func lineWaiting(in *bufio.Reader) bool {
	buffered, _ := in.Peek(in.Buffered())
	return bytes.IndexByte(buffered, '\n') >= 0
}

// readLine reads up to "\n", as bufio.ScanLines does: without the "\n" and a
// "\r" before it, and a last line without "\n" too.
func readLine(in *bufio.Reader) (string, error) {
	var line []byte
	for {
		chunk, err := in.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLineBytes {
			return "", bufio.ErrTooLong
		}
		switch {
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF && len(line) == 0:
			return "", io.EOF
		case err != nil && err != io.EOF:
			return "", err
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		return string(line), nil
	}
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
