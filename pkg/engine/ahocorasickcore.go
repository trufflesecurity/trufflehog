package engine

import (
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// detectorKey is used to identify a detector in the keywordsToDetectors map.
// Multiple detectors can have the same detector type but different versions.
// This allows us to identify a detector by its type and version.
type detectorKey struct {
	detectorType detectorspb.DetectorType
	version      int
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
	keywordsToDetectors map[string][]detectorKey
	detectorsByKey      map[detectorKey]detectors.Detector
}

// NewAhoCorasickCore allocates and initializes a new instance of AhoCorasickCore. It uses the
// provided detector slice to create a map from keywords to detectors and build the Aho-Corasick
// prefilter trie.
func NewAhoCorasickCore(allDetectors []detectors.Detector) *AhoCorasickCore {
	keywordsToDetectors := make(map[string][]detectorKey)
	detectorsByKey := make(map[detectorKey]detectors.Detector, len(allDetectors))
	var keywords []string
	for _, d := range allDetectors {
		key := createDetectorKey(d)
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

// MatchString performs a string match using the Aho-Corasick algorithm, returning an array of matches.
// Designed for internal use within the AhoCorasickCore component.
func (ac *AhoCorasickCore) MatchString(input string) []*ahocorasick.Match {
	return ac.prefilter.MatchString(strings.ToLower(input))
}

// PopulateDetectorsByMatch populates the given detectorMap based on the Aho-Corasick match results.
// This method is designed to reuse the same map for performance optimization,
// reducing the need for repeated allocations within each detector worker in the engine.
func (ac *AhoCorasickCore) PopulateDetectorsByMatch(match *ahocorasick.Match, detectors map[detectorspb.DetectorType]detectors.Detector) bool {
	matchedDetectorKeys, ok := ac.keywordsToDetectors[match.MatchString()]
	if !ok {
		return false
	}
	for _, key := range matchedDetectorKeys {
		detectors[key.detectorType] = ac.detectorsByKey[key]
	}
	return true
}

// createDetectorKey creates a unique key for each detector. This key based on type and version,
// it ensures faster lookups and reduces redundancy in our main detector store.
func createDetectorKey(d detectors.Detector) detectorKey {
	detectorType := d.Type()
	var version int
	if v, ok := d.(detectors.Versioner); ok {
		version = v.Version()
	}
	return detectorKey{detectorType: detectorType, version: version}
}
