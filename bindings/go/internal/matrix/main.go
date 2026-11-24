// Command matrix writes the Go binding's cells of the benchmark matrix
// (bench/matrix/), on the corpus bench/matrix/corpus.mjs writes, in the rows
// every harness of the matrix writes.
//
//	go run ./internal/matrix <corpus dir> <out.jsonl>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	anonyma "github.com/izaccavalheiro/anonyma-go"
)

// median is the median milliseconds of one run of run, over at least 5 samples
// and 300 ms. The clock can be coarse (about 0.5 ms on Windows), so a sample
// times enough runs to last at least 10 ms, and is divided by their number.
func median(run func()) float64 {
	run()
	repeat := 1
	for {
		t := time.Now()
		for i := 0; i < repeat; i++ {
			run()
		}
		if time.Since(t) >= 10*time.Millisecond {
			break
		}
		repeat *= 4
	}
	var samples []float64
	start := time.Now()
	for len(samples) < 5 || (time.Since(start) < 300*time.Millisecond && len(samples) < 50) {
		t := time.Now()
		for i := 0; i < repeat; i++ {
			run()
		}
		samples = append(samples, float64(time.Since(t).Nanoseconds())/1e6/float64(repeat))
	}
	sort.Float64s(samples)
	return samples[len(samples)/2]
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: matrix <corpus dir> <out.jsonl>")
		os.Exit(2)
	}
	dir, outPath := os.Args[1], os.Args[2]
	engine, err := anonyma.NewEngine(anonyma.Options{})
	if err != nil {
		panic(err)
	}
	defer engine.Close()

	var out strings.Builder
	row := func(shape string, entrySize, entries, threads int, ms float64, matches int) {
		line, _ := json.Marshal(map[string]any{
			"engine": "go", "runtime": runtime.Version(), "op": "detect", "shape": shape,
			"entrySize": entrySize, "entries": entries, "threads": threads, "medianMs": ms,
			"perEntryUs": ms * 1000 / float64(entries), "matches": matches,
		})
		fmt.Println(string(line))
		out.Write(line)
		out.WriteByte('\n')
	}

	for _, name := range []string{"1k", "100k", "1m"} {
		raw, err := os.ReadFile(filepath.Join(dir, "single-"+name+".txt"))
		if err != nil {
			panic(err)
		}
		text := string(raw)
		found, err := engine.Detect(text)
		if err != nil {
			panic(err)
		}
		row("single", len(text), 1, 1, median(func() { _, _ = engine.Detect(text) }), len(found))
	}

	raw, err := os.ReadFile(filepath.Join(dir, "entries.json"))
	if err != nil {
		panic(err)
	}
	var entries []string
	if err := json.Unmarshal(raw, &entries); err != nil {
		panic(err)
	}
	size := 0
	for _, e := range entries {
		size += len(e)
	}
	size /= len(entries)
	each := 0
	for _, e := range entries {
		found, _ := engine.Detect(e)
		each += len(found)
	}
	row("each", size, len(entries), 1, median(func() {
		for _, e := range entries {
			_, _ = engine.Detect(e)
		}
	}), each)
	// The same calls spread over goroutines, one engine shared by all.
	cores := runtime.NumCPU()
	for _, threads := range []int{2, 4, cores} {
		if threads <= 1 || threads > cores || (threads == cores && (cores == 2 || cores == 4)) {
			continue
		}
		chunk := (len(entries) + threads - 1) / threads
		row("each", size, len(entries), threads, median(func() {
			var wg sync.WaitGroup
			for start := 0; start < len(entries); start += chunk {
				end := min(start+chunk, len(entries))
				wg.Add(1)
				go func(part []string) {
					defer wg.Done()
					for _, e := range part {
						_, _ = engine.Detect(e)
					}
				}(entries[start:end])
			}
			wg.Wait()
		}), each)
	}

	batched, err := engine.DetectBatch(entries)
	if err != nil {
		panic(err)
	}
	batch := 0
	for _, found := range batched {
		batch += len(found)
	}
	// DetectBatch runs on the core's rayon pool, one thread per core.
	row("batch", size, len(entries), runtime.NumCPU(), median(func() { _, _ = engine.DetectBatch(entries) }), batch)

	if err := os.WriteFile(outPath, []byte(out.String()), 0o644); err != nil {
		panic(err)
	}
}
