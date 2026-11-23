package anonyma

// ScanOptions configures [Scan], as compilePipeline does in the TypeScript package.
type ScanOptions struct {
	// Categories to detect; every category when empty.
	Categories []string `json:"categories,omitempty"`
	// "precise" (the default) or "legacy", the detectors of [Detect].
	Detection string `json:"detection,omitempty"`
	// Use the aggressive detectors.
	Aggressive bool `json:"aggressive,omitempty"`
	// Drop spans below this confidence.
	MinConfidence float64 `json:"minConfidence,omitempty"`
}

// Span is a detection of [Scan]. Start and End are byte offsets.
type Span struct {
	Category   string  `json:"category"`
	Detector   string  `json:"detector"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
	// Residual is true for the part of a detection that a stronger overlapping
	// one left uncovered.
	Residual bool `json:"residual"`
}

// Scan runs the span engine: the precise detectors, with overlaps resolved by
// covering, in document order.
func Scan(text string, opts ScanOptions) ([]Span, error) {
	// aggressive and minConfidence are sent even when zero, as they always were.
	fields, err := optionFields(struct {
		Categories    []string `json:"categories,omitempty"`
		Detection     string   `json:"detection,omitempty"`
		Aggressive    bool     `json:"aggressive"`
		MinConfidence float64  `json:"minConfidence"`
	}{opts.Categories, opts.Detection, opts.Aggressive, opts.MinConfidence})
	if err != nil {
		return nil, err
	}
	var out struct {
		Spans []Span `json:"spans"`
	}
	if err := call("scan", textInput(text, fields), &out); err != nil {
		return nil, err
	}
	return out.Spans, nil
}
