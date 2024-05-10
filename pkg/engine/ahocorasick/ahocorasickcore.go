package ahocorasick

import (
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
}

// NewAhoCorasickCore allocates and initializes a new instance of AhoCorasickCore. It uses the
// provided detector slice to create a map from keywords to detectors and build the Aho-Corasick
// prefilter trie.
func NewAhoCorasickCore(allDetectors []detectors.Detector) *AhoCorasickCore {
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

	return &AhoCorasickCore{
		keywordsToDetectors: keywordsToDetectors,
		detectorsByKey:      detectorsByKey,
		prefilter:           *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build(),
	}
}

// DetectorMatch represents a detected pattern's metadata in a data chunk.
// It encapsulates the key identifying a specific detector, the detector instance itself,
// and the start and end offsets of the matched keyword in the chunk.
type DetectorMatch struct {
	Key DetectorKey
	detectors.Detector
	matchSpans []matchSpan
}

// MatchSpan represents a single occurrence of a matched keyword in the chunk.
// It contains the start and end byte offsets of the matched keyword within the chunk.
type matchSpan struct {
	startOffset int64
	endOffset   int64
}

// Matches returns a slice of byte slices, each representing a matched portion of the chunk data.
func (d *DetectorMatch) Matches(chunkData []byte) [][]byte {
	matches := make([][]byte, len(d.matchSpans))
	for i, m := range d.matchSpans {
		end := min(m.endOffset, int64(len(chunkData)))
		matches[i] = chunkData[m.startOffset:end]
	}
	return matches
}

const maxMatchLength int64 = 512

// FindDetectorMatches finds the matching detectors for a given chunk of data using the Aho-Corasick algorithm.
// It returns a slice of DetectorMatch instances, each containing the detector key, detector,
// and a slice of matches.
// Each matchSpan represents a position in the chunk data where a keyword was found,
// along with a corresponding end position.
// The end position is determined based on the detector's ProvideMaxSecretSize if it implements the
// MaxSecretSizeProvider interface, or falls back to the default maxMatchLength.
// Adjacent or overlapping matches are merged to avoid duplicating or overlapping the matched
// portions of the chunk data.
func (ac *AhoCorasickCore) FindDetectorMatches(chunkData string) []DetectorMatch {
	matches := ac.prefilter.MatchString(strings.ToLower(chunkData))

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
			maxSize := maxMatchLength
			if sizeProvider, ok := detectorMatch.Detector.(detectors.MaxSecretSizeProvider); ok {
				maxSize = sizeProvider.ProvideMaxSecretSize()
			}

			endIdx := startIdx + maxSize
			if endIdx > int64(len(chunkData)) {
				endIdx = int64(len(chunkData))
			}
			detectorMatch.matchSpans = append(detectorMatch.matchSpans, matchSpan{startOffset: startIdx, endOffset: endIdx})
		}
	}

	uniqueDetectors := make([]DetectorMatch, 0, len(detectorMatches))
	for _, detectorMatch := range detectorMatches {
		detectorMatch.matchSpans = mergeMatches(detectorMatch.matchSpans)
		uniqueDetectors = append(uniqueDetectors, *detectorMatch)
	}

	return uniqueDetectors
}

// mergeMatches merges overlapping or adjacent matchSpans into a single matchSpan.
// It takes a slice of matchSpans and returns a new slice with merged matchSpans.
func mergeMatches(matches []matchSpan) []matchSpan {
	if len(matches) <= 1 {
		return matches
	}

	merged := make([]matchSpan, 0, len(matches))
	current := matches[0]

	for i := 1; i < len(matches); i++ {
		if matches[i].startOffset <= current.endOffset {
			if matches[i].endOffset > current.endOffset {
				current.endOffset = matches[i].endOffset
			}
		} else {
			merged = append(merged, current)
			current = matches[i]
		}
	}

	merged = append(merged, current)
	return merged
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
