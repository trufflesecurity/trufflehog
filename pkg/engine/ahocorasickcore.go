package engine

import (
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

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
	keywordsToDetectorTypes map[string][]detectorspb.DetectorType
	detectorsByType         map[detectorspb.DetectorType]detectors.Detector
}

// NewAhoCorasickCore allocates and initializes a new instance of AhoCorasickCore. It uses the
// provided detector slice to create a map from keywords to detectors and build the Aho-Corasick
// prefilter trie.
func NewAhoCorasickCore(allDetectors []detectors.Detector) *AhoCorasickCore {
	keywordsToDetectorTypes := make(map[string][]detectorspb.DetectorType)
	detectorsByType := make(map[detectorspb.DetectorType]detectors.Detector, len(allDetectors))
	var keywords []string
	for _, d := range allDetectors {
		detectorsByType[d.Type()] = d
		for _, kw := range d.Keywords() {
			kwLower := strings.ToLower(kw)
			keywords = append(keywords, kwLower)
			keywordsToDetectorTypes[kwLower] = append(keywordsToDetectorTypes[kwLower], d.Type())
		}
	}

	return &AhoCorasickCore{
		keywordsToDetectorTypes: keywordsToDetectorTypes,
		detectorsByType:         detectorsByType,
		prefilter:               *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build(),
	}
}

// MatchString performs a string match using the Aho-Corasick algorithm, returning an array of matches.
// Designed for internal use within the AhoCorasickCore component.
func (ac *AhoCorasickCore) MatchString(input string) []*ahocorasick.Match {
	return ac.prefilter.MatchString(strings.ToLower(input))
}

// PopulateDetectorsByMatch populates the given detectorMap based on the Aho-Corasick match results.
// This method is designed to reuse the same map for performance optimization,
// reducing the need for repeated allocations within each detector worker in the engine.
func (ac *AhoCorasickCore) PopulateDetectorsByMatch(match *ahocorasick.Match, detectors map[detectorspb.DetectorType]detectors.Detector) bool {
	matchedDetectorTypes, ok := ac.keywordsToDetectorTypes[match.MatchString()]
	if !ok {
		return false
	}
	for _, t := range matchedDetectorTypes {
		detectors[t] = ac.detectorsByType[t]
	}
	return true
}
