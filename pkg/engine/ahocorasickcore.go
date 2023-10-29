package engine

import (
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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

// DetectorInfo is used to store a detector and whether it should be verified.
type DetectorInfo struct {
	detectors.Detector
	ShouldVerify bool
}

// AhoCorasickCore encapsulates the operations and data structures used for keyword matching via the
// Aho-Corasick algorithm. It is responsible for constructing and managing the trie for efficient
// substring searches, as well as mapping keywords to their associated detectors for rapid lookups.
type AhoCorasickCore struct {
	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words. (keywords from the rules in the config)
	prefilter ahocorasick.Trie
	// Maps for efficient lookups during detection.
	detectorTypeToDetectorInfo map[detectorKey]DetectorInfo
	detectors                  map[bool][]detectors.Detector
	keywordsToDetectors        map[string][]detectorKey
}

// NewAhoCorasickCore allocates and initializes a new instance of AhoCorasickCore.
// It creates an empty keyword-to-detectors map for future string matching operations.
// The map detectorTypeToDetectorInfo is pre-allocated based on the size of detectors
// provided, for efficient storage and lookup of detector information.
func NewAhoCorasickCore(detectors map[bool][]detectors.Detector) *AhoCorasickCore {
	return &AhoCorasickCore{
		keywordsToDetectors:        make(map[string][]detectorKey),
		detectors:                  detectors,
		detectorTypeToDetectorInfo: make(map[detectorKey]DetectorInfo, len(detectors[true])+len(detectors[false])),
	}
}

// Setup initializes the internal state of AhoCorasickCore to prepare it for keyword matching.
// This involves pre-filtering setup and lookup optimization, critical for the engine's performance.
func (ac *AhoCorasickCore) Setup(ctx context.Context) {
	// Prepare maps for fast detector lookups, instead of scanning through an array of detectors for every chunk.
	var keywords []string
	for verify, detectorsSet := range ac.detectors {
		for _, d := range detectorsSet {
			key := createDetectorKey(d)
			ac.detectorTypeToDetectorInfo[key] = DetectorInfo{Detector: d, ShouldVerify: verify}
			keywords = ac.extractAndMapKeywords(d, key, keywords)
		}
	}

	// Use the Ahocorasick algorithm to create a trie structure for efficient keyword matching.
	// This ensures that we can rapidly match against a vast set of keywords without individually comparing each one.
	ac.prefilter = *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()
	ctx.Logger().V(4).Info("AhoCorasickCore Setup complete")
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

// extractAndMapKeywords captures keywords associated with each detector and maps them.
// This allows us to quickly determine which detectors are relevant based on the presence of certain keywords.
func (ac *AhoCorasickCore) extractAndMapKeywords(d detectors.Detector, key detectorKey, keywords []string) []string {
	for _, kw := range d.Keywords() {
		kwLower := strings.ToLower(kw)
		keywords = append(keywords, kwLower)
		ac.keywordsToDetectors[kwLower] = append(ac.keywordsToDetectors[kwLower], key)
	}
	return keywords
}

// MatchString performs a string match using the Aho-Corasick algorithm, returning an array of matches.
// Designed for internal use within the AhoCorasickCore component.
func (ac *AhoCorasickCore) MatchString(input string) []*ahocorasick.Match {
	return ac.prefilter.MatchString(strings.ToLower(input))
}

// PopulateDetectorsByMatch populates the given detectorMap based on the Aho-Corasick match results.
// This method is designed to reuse the same map for performance optimization,
// reducing the need for repeated allocations within each detector worker in the engine.
func (ac *AhoCorasickCore) PopulateDetectorsByMatch(match *ahocorasick.Match, detectors map[detectorspb.DetectorType]DetectorInfo) bool {
	matchedKeys, ok := ac.keywordsToDetectors[match.MatchString()]
	if !ok {
		return false
	}
	for _, key := range matchedKeys {
		detectors[key.detectorType] = ac.detectorTypeToDetectorInfo[key]
	}
	return true
}
