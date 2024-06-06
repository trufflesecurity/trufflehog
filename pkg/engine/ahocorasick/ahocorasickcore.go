package ahocorasick

import (
	"bytes"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// DetectorKey is used to identify a detector in the keywordsToDetectors map.
// Multiple detectors can have the same detector type but different versions.
// This allows us to identify a detector by its type and version. An
// additional (optional) field is provided to disambiguate multiple custom
// detectors. This type is exported even though none of its fields are so
// that the AhoCorasickCore can populate passed-in maps keyed on this type
// without exposing any of its internals to consumers.
type DetectorKey struct {
	detectorType       detectorspb.DetectorType
	version            int
	customDetectorName string
}

// Type returns the detector type of the key.
func (k DetectorKey) Type() detectorspb.DetectorType { return k.detectorType }

// spanCalculator is an interface that defines a method for calculating a match span
// in the chunk data. This allows for different strategies to be used without changing the core logic.
type spanCalculator interface {
	calculateSpan(params spanCalculationParams) matchSpan
}

// spanCalculationParams provides the necessary context for calculating match spans,
// including the starting index in the chunk, the chunk data itself, and the detector being used.
type spanCalculationParams struct {
	startIdx  int64
	chunkData []byte
	detector  detectors.Detector
}

// EntireChunkSpanCalculator is a strategy that calculates the match span to use the entire chunk data.
// This is used when we want to match against the full length of the provided chunk.
type EntireChunkSpanCalculator struct{}

// calculateSpan returns the match span as the length of the chunk data,
// effectively using the entire chunk for matching.
func (e *EntireChunkSpanCalculator) calculateSpan(params spanCalculationParams) matchSpan {
	return matchSpan{startOffset: 0, endOffset: int64(len(params.chunkData))}
}

// maxMatchLengthSpanCalculator is a strategy that calculates match spans based on a default max
// match length or values provided by detectors. This allows for more granular control over the match span.
type maxMatchLengthSpanCalculator struct{ maxMatchLength int64 }

// newMaxMatchLengthSpanCalculator creates a new instance of maxMatchLengthSpanCalculator with the
// specified max match length.
func newMaxMatchLengthSpanCalculator(maxMatchLength int64) *maxMatchLengthSpanCalculator {
	return &maxMatchLengthSpanCalculator{maxMatchLength: maxMatchLength}
}

// calculateSpans computes the match spans based on the start index and the max match length.
// If the detector provides an override value, it uses that instead of the default max match length.
func (m *maxMatchLengthSpanCalculator) calculateSpan(params spanCalculationParams) matchSpan {
	maxSize := m.maxMatchLength

	switch d := params.detector.(type) {
	case detectors.MultiPartCredentialProvider:
		maxSize = d.MaxCredentialSpan()
	case detectors.MaxSecretSizeProvider:
		maxSize = d.MaxSecretSize()
	default: // Use the default max match length
	}
	endIdx := params.startIdx + maxSize
	if endIdx > int64(len(params.chunkData)) {
		endIdx = int64(len(params.chunkData))
	}

	return matchSpan{startOffset: params.startIdx, endOffset: endIdx}
}

// AhoCorasickCoreOption is a functional option type for configuring an AhoCorasickCore instance.
type AhoCorasickCoreOption func(*AhoCorasickCore)

// WithSpanCalculator sets the span calculator for AhoCorasickCore.
func WithSpanCalculator(spanCalculator spanCalculator) AhoCorasickCoreOption {
	return func(ac *AhoCorasickCore) { ac.spanCalculator = spanCalculator }
}

// AhoCorasickCore encapsulates the operations and data structures used for keyword matching via the
// Aho-Corasick algorithm. It is responsible for constructing and managing the trie for efficient
// substring searches, as well as mapping keywords to their associated detectors for rapid lookups.
type AhoCorasickCore struct {
	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words. (keywords from the rules in the config)
	prefilter ahocorasick.Trie
	// Maps for efficient lookups during detection.
	// (This implementation maps in two layers: from keywords to detector
	// type and then again from detector type to detector. We could
	// go straight from keywords to detectors but doing it this way makes
	// some consuming code a little cleaner.)
	keywordsToDetectors map[string][]DetectorKey
	detectorsByKey      map[DetectorKey]detectors.Detector
	spanCalculator      spanCalculator // Strategy for calculating match spans
}

// NewAhoCorasickCore allocates and initializes a new instance of AhoCorasickCore. It uses the
// provided detector slice to create a map from keywords to detectors and build the Aho-Corasick
// prefilter trie.
func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...AhoCorasickCoreOption) *AhoCorasickCore {
	keywordsToDetectors := make(map[string][]DetectorKey)
	detectorsByKey := make(map[DetectorKey]detectors.Detector, len(allDetectors))
	var keywords []string
	for _, d := range allDetectors {
		key := CreateDetectorKey(d)
		detectorsByKey[key] = d
		for _, kw := range d.Keywords() {
			kwLower := strings.ToLower(kw)
			keywords = append(keywords, kwLower)
			keywordsToDetectors[kwLower] = append(keywordsToDetectors[kwLower], key)
		}
	}

	const maxMatchLength int64 = 512
	ac := &AhoCorasickCore{
		keywordsToDetectors: keywordsToDetectors,
		detectorsByKey:      detectorsByKey,
		prefilter:           *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build(),
		spanCalculator:      newMaxMatchLengthSpanCalculator(maxMatchLength), // Default span calculator
	}

	for _, opt := range opts {
		opt(ac)
	}

	return ac
}

// DetectorMatch represents a detected pattern's metadata in a data chunk.
// It encapsulates the key identifying a specific detector, the detector instance itself,
// the start and end offsets of the matched keyword in the chunk, and the matched portions of the chunk data.
type DetectorMatch struct {
	Key DetectorKey
	detectors.Detector
	matchSpans []matchSpan

	// matches is a slice of byte slices, each representing a matched portion of the chunk data.
	matches [][]byte
}

// MatchSpan represents a single occurrence of a matched keyword in the chunk.
// It contains the start and end byte offsets of the matched keyword within the chunk.
type matchSpan struct {
	startOffset int64
	endOffset   int64
}

// addMatchSpan adds a match span to the DetectorMatch instance.
func (d *DetectorMatch) addMatchSpan(spans ...matchSpan) {
	d.matchSpans = append(d.matchSpans, spans...)
}

// mergeMatches merges overlapping or adjacent matchSpans into a single matchSpan.
// It updates the matchSpans field with the merged spans.
func (d *DetectorMatch) mergeMatches() {
	if len(d.matchSpans) <= 1 {
		return
	}

	merged := make([]matchSpan, 0, len(d.matchSpans))
	current := d.matchSpans[0]

	for i := 1; i < len(d.matchSpans); i++ {
		if d.matchSpans[i].startOffset <= current.endOffset {
			if d.matchSpans[i].endOffset > current.endOffset {
				current.endOffset = d.matchSpans[i].endOffset
			}
			continue
		}
		merged = append(merged, current)
		current = d.matchSpans[i]
	}

	merged = append(merged, current)
	d.matchSpans = merged
}

// extractMatches extracts the matched portions from the chunk data and stores them in the matches field.
func (d *DetectorMatch) extractMatches(chunkData []byte) {
	d.matches = make([][]byte, len(d.matchSpans))
	for i, m := range d.matchSpans {
		d.matches[i] = chunkData[m.startOffset:m.endOffset]
	}
}

// Matches returns a slice of byte slices, each representing a matched portion of the chunk data.
func (d *DetectorMatch) Matches() [][]byte { return d.matches }

// FindDetectorMatches finds the matching detectors for a given chunk of data using the Aho-Corasick algorithm.
// It returns a slice of DetectorMatch instances, each containing the detector key, detector,
// a slice of matchSpans, and the corresponding matched portions of the chunk data.
//
// Each matchSpan represents a position in the chunk data where a keyword was found,
// along with the corresponding span (start and end positions).
// The span is determined based on the configured spanCalculator strategy.
// Adjacent or overlapping matches are merged to avoid duplicating or overlapping the matched
// portions of the chunk data.
//
// The matches field contains the actual byte slices of the matched portions from the chunk data.
func (ac *AhoCorasickCore) FindDetectorMatches(chunkData []byte) []*DetectorMatch {
	matches := ac.prefilter.Match(bytes.ToLower(chunkData))

	matchCount := len(matches)
	if matchCount == 0 {
		return nil
	}

	detectorMatches := make(map[DetectorKey]*DetectorMatch)

	for _, m := range matches {
		for _, k := range ac.keywordsToDetectors[m.MatchString()] {
			if _, exists := detectorMatches[k]; !exists {
				detector := ac.detectorsByKey[k]
				detectorMatches[k] = &DetectorMatch{
					Key:        k,
					Detector:   detector,
					matchSpans: make([]matchSpan, 0),
				}
			}

			detectorMatch := detectorMatches[k]
			startIdx := m.Pos()
			span := ac.spanCalculator.calculateSpan(
				spanCalculationParams{
					startIdx:  startIdx,
					chunkData: chunkData,
					detector:  detectorMatch.Detector,
				},
			)
			detectorMatch.addMatchSpan(span)
		}
	}

	uniqueDetectors := make([]*DetectorMatch, 0, len(detectorMatches))
	for _, detectorMatch := range detectorMatches {
		// Merge overlapping or adjacent match spans.
		detectorMatch.mergeMatches()
		detectorMatch.extractMatches(chunkData)

		uniqueDetectors = append(uniqueDetectors, detectorMatch)
	}

	return uniqueDetectors
}

// CreateDetectorKey creates a unique key for each detector from its type, version, and, for
// custom regex detectors, its name.
func CreateDetectorKey(d detectors.Detector) DetectorKey {
	detectorType := d.Type()
	var version int
	if v, ok := d.(detectors.Versioner); ok {
		version = v.Version()
	}
	var customDetectorName string
	if r, ok := d.(*custom_detectors.CustomRegexWebhook); ok {
		customDetectorName = r.GetName()
	}
	return DetectorKey{detectorType: detectorType, version: version, customDetectorName: customDetectorName}
}

func (ac *AhoCorasickCore) KeywordsToDetectors() map[string][]DetectorKey {
	return ac.keywordsToDetectors
}
