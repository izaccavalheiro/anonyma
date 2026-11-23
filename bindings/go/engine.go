package anonyma

/*
#include "anonyma.h"
*/
import "C"

import (
	"runtime"
	"sync"
)

// Engine detects and anonymizes with options parsed and detectors built once,
// for callers that make many calls with the same options. It is safe for
// concurrent use. Close it when done; a finalizer frees it otherwise.
//
// Unlike [Detect], an Engine reports an error for categories the core does not
// detect in full unless Options.AllowPartial is set, as [Anonymize] does.
type Engine struct {
	mu  sync.RWMutex
	ptr *C.AnonymaEngine
}

// NewEngine builds an engine for opts.
func NewEngine(opts Options) (*Engine, error) {
	options, err := marshalInput(opts)
	if err != nil {
		return nil, err
	}
	var failure *C.char
	ptr := C.anonyma_engine_new(cPointer(options), &failure)
	if ptr == nil {
		if failure == nil {
			return nil, &Error{Message: "the engine could not be built"}
		}
		return nil, decode(failure, nil)
	}
	e := &Engine{ptr: ptr}
	runtime.SetFinalizer(e, (*Engine).Close)
	return e, nil
}

// Close frees the engine. Later calls return [ErrEngineClosed].
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ptr != nil {
		C.anonyma_engine_free(e.ptr)
		e.ptr = nil
	}
	return nil
}

func (e *Engine) call(op string, input []byte, out any) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.ptr == nil {
		return ErrEngineClosed
	}
	cop := cString(op)
	return decode(C.anonyma_engine_call(e.ptr, cPointer(cop), cPointer(input)), out)
}

// Detect finds every value of personal data in text, as [Detect] does.
func (e *Engine) Detect(text string) ([]Match, error) {
	var out struct {
		Matches []Match `json:"matches"`
	}
	if err := e.call("detect", textInput(text, nil), &out); err != nil {
		return nil, err
	}
	return out.Matches, nil
}

// Anonymize replaces every value found with its category's strategy, as [Anonymize] does.
func (e *Engine) Anonymize(text string) (string, error) {
	var out struct {
		Text string `json:"text"`
	}
	if err := e.call("anonymize", textInput(text, nil), &out); err != nil {
		return "", err
	}
	return out.Text, nil
}

// textsInput builds `{"texts":[…],"offsets":"bytes"}` and a NUL byte.
func textsInput(texts []string) []byte {
	size := 32
	for _, text := range texts {
		size += len(text) + 3
	}
	buf := make([]byte, 0, size)
	buf = append(buf, `{"texts":[`...)
	for i, text := range texts {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendJSONString(buf, text)
	}
	buf = append(buf, `],"offsets":"bytes"}`...)
	return append(buf, 0)
}

// DetectBatch returns [Engine.Detect] of each text, in order, in one call:
// short texts are scanned together, which costs far less than a call each.
func (e *Engine) DetectBatch(texts []string) ([][]Match, error) {
	var out struct {
		Results []struct {
			Matches []Match `json:"matches"`
		} `json:"results"`
	}
	if err := e.call("detect_batch", textsInput(texts), &out); err != nil {
		return nil, err
	}
	matches := make([][]Match, len(out.Results))
	for i, result := range out.Results {
		matches[i] = result.Matches
	}
	return matches, nil
}

// AnonymizeBatch returns [Engine.Anonymize] of each text, in order, in one
// call. It fails as a whole on the first text a strategy fails on.
func (e *Engine) AnonymizeBatch(texts []string) ([]string, error) {
	var out struct {
		Results []struct {
			Text string `json:"text"`
		} `json:"results"`
	}
	if err := e.call("anonymize_batch", textsInput(texts), &out); err != nil {
		return nil, err
	}
	anonymized := make([]string, len(out.Results))
	for i, result := range out.Results {
		anonymized[i] = result.Text
	}
	return anonymized, nil
}
