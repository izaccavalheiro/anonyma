package anonyma

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// lineByLine is what NewReader wrote when it anonymized one line per call.
func lineByLine(t *testing.T, input string) string {
	t.Helper()
	engine, err := NewEngine(emails)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		line, err := engine.Anonymize(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		out.WriteString(line + "\n")
	}
	return out.String()
}

func readerInput() string {
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		switch i % 4 {
		case 0:
			fmt.Fprintf(&b, "José %d: user%d@example.com\r\n", i, i)
		case 1:
			b.WriteString("\n")
		default:
			fmt.Fprintf(&b, "line %d with nothing\n", i)
		}
	}
	b.WriteString("last ana@example.com\r")
	return b.String()
}

func TestNewReaderWritesWhatOneCallPerLineWrote(t *testing.T) {
	input := readerInput()
	out, err := io.ReadAll(NewReader(strings.NewReader(input), emails))
	if err != nil {
		t.Fatal(err)
	}
	if want := lineByLine(t, input); string(out) != want {
		t.Fatalf("got %d bytes, want %d", len(out), len(want))
	}
}

func TestNewReaderCutsBatchesByLinesAndBytes(t *testing.T) {
	defer func(lines, bytes int) { batchLines, batchBytes = lines, bytes }(batchLines, batchBytes)
	input := readerInput()
	for _, limits := range [][2]int{{3, 1 << 20}, {4096, 64}} {
		batchLines, batchBytes = limits[0], limits[1]
		out, err := io.ReadAll(NewReader(strings.NewReader(input), emails))
		if err != nil || string(out) != lineByLine(t, input) {
			t.Fatalf("limits %v: %d bytes, %v", limits, len(out), err)
		}
	}
}

func TestNewReaderAnswersEachLineOfAnInteractiveStream(t *testing.T) {
	in, feed := io.Pipe()
	out := bufio.NewReader(NewReader(in, emails))
	for i := 0; i < 3; i++ {
		go fmt.Fprintf(feed, "turn %d ana@example.com\n", i)
		got := make(chan string, 1)
		go func() {
			line, _ := out.ReadString('\n')
			got <- line
		}()
		select {
		case line := <-got:
			if line != fmt.Sprintf("turn %d [REDACTED]\n", i) {
				t.Fatalf("got %q", line)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the line was held back")
		}
	}
	feed.Close()
	if rest, err := io.ReadAll(out); err != nil || len(rest) != 0 {
		t.Fatalf("got %q, %v", rest, err)
	}
}

func TestNewReaderRefusesALineTooLong(t *testing.T) {
	defer func(limit int) { maxLineBytes = limit }(maxLineBytes)
	maxLineBytes = 10
	out, err := io.ReadAll(NewReader(strings.NewReader("short\n"+strings.Repeat("x", 11)+"\n"), emails))
	if !errors.Is(err, bufio.ErrTooLong) || string(out) != "short\n" {
		t.Fatalf("got %q, %v", out, err)
	}
}

// failing returns its text, then an error.
type failing struct{ text string }

func (f *failing) Read(p []byte) (int, error) {
	if f.text == "" {
		return 0, errors.New("disk on fire")
	}
	n := copy(p, f.text)
	f.text = f.text[n:]
	return n, nil
}

func TestNewReaderWritesTheLinesBeforeAReadError(t *testing.T) {
	out, err := io.ReadAll(NewReader(&failing{text: "a ana@example.com\nb"}, emails))
	if err == nil || err.Error() != "disk on fire" || string(out) != "a [REDACTED]\n" {
		t.Fatalf("got %q, %v", out, err)
	}
	if _, err := io.ReadAll(NewReader(strings.NewReader("x"), Options{Categories: []string{"nope"}})); err == nil {
		t.Fatal("expected an error for options an engine cannot be built from")
	}
}
