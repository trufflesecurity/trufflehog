package engine

import (
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// ahoCorasickCore encapsulates the operations and data structures used for keyword matching via the
// Aho-Corasick algorithm. It is responsible for constructing and managing the trie for efficient
// substring searches, as well as mapping keywords to their associated detectors for rapid lookups.
type ahoCorasickCore struct {
	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter ahocorasick.Trie
	// Maps for efficient lookups during detection.
	detectorTypeToDetectorInfo map[detectorKey]detectorInfo
	detectors                  map[bool][]detectors.Detector
	keywordsToDetectors        map[string][]detectorKey
}

// newAhoCorasickCore allocates and initializes a new ahoCorasickCore.
// It sets up an empty keyword-to-detectors map, preparing it for subsequent population.
func newAhoCorasickCore(detectors map[bool][]detectors.Detector) *ahoCorasickCore {
	return &ahoCorasickCore{
		keywordsToDetectors:        make(map[string][]detectorKey),
		detectors:                  detectors,
		detectorTypeToDetectorInfo: make(map[detectorKey]detectorInfo, len(detectors[true])+len(detectors[false])),
	}
}

// setup initializes the internal state of ahoCorasickCore to prepare it for keyword matching.
// This involves pre-filtering setup and lookup optimization, critical for the engine's performance.
func (ac *ahoCorasickCore) setup(ctx context.Context) {
	ac.buildLookups(ctx)
}

// buildLookups prepares maps for fast detector lookups. Instead of scanning through an array of
// detectors for every chunk, this lookup optimization  provides rapid access to relevant detectors using keywords.
func (ac *ahoCorasickCore) buildLookups(ctx context.Context) {
	var keywords []string
	for verify, detectorsSet := range ac.detectors {
		for _, d := range detectorsSet {
			key := ac.classifyDetector(d, verify)
			keywords = ac.extractAndMapKeywords(d, key, keywords)
		}
	}

	// Implementing a trie aids in substring searches among the keywords.
	// This is crucial when you have large sets of strings to search through.
	ac.buildTrie(keywords)
	ctx.Logger().V(4).Info("engine lookups built")
}

// classifyDetector assigns a unique key for each detector. This key based on type and version,
// ensures faster lookups and reduces redundancy in our main detector store.
func (ac *ahoCorasickCore) classifyDetector(d detectors.Detector, shouldVerify bool) detectorKey {
	detectorType := d.Type()
	var version int
	if v, ok := d.(detectors.Versioner); ok {
		version = v.Version()
	}
	key := detectorKey{detectorType: detectorType, version: version}
	ac.detectorTypeToDetectorInfo[key] = detectorInfo{Detector: d, shouldVerify: shouldVerify}
	return key
}

// extractAndMapKeywords captures keywords associated with each detector and maps them.
// This allows us to quickly determine which detectors are relevant based on the presence of certain keywords.
func (ac *ahoCorasickCore) extractAndMapKeywords(d detectors.Detector, key detectorKey, keywords []string) []string {
	for _, kw := range d.Keywords() {
		kwLower := strings.ToLower(kw)
		keywords = append(keywords, kwLower)
		ac.keywordsToDetectors[kwLower] = append(ac.keywordsToDetectors[kwLower], key)
	}
	return keywords
}

// buildTrie uses the Ahocorasick algorithm to create a trie structure for efficient keyword matching.
// This ensures that we can rapidly match against a vast set of keywords without individually comparing each one.
func (ac *ahoCorasickCore) buildTrie(keywords []string) {
	ac.prefilter = *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()
}

// matchString performs a string match using the Aho-Corasick algorithm, returning an array of matches.
// Designed for internal use within the ahoCorasickCore component.
func (ac *ahoCorasickCore) matchString(input string) []*ahocorasick.Match {
	return ac.prefilter.MatchString(strings.ToLower(input))
}

// populateDetectorsByMatch populates the given detectorMap based on the Aho-Corasick match results.
// This method is designed to reuse the same map for performance optimization,
// reducing the need for repeated allocations.
func (ac *ahoCorasickCore) populateDetectorsByMatch(match *ahocorasick.Match, detectors map[detectorspb.DetectorType]detectorInfo) bool {
	matchedKeys, ok := ac.keywordsToDetectors[match.MatchString()]
	if !ok {
		return false
	}
	for _, key := range matchedKeys {
		detectors[key.detectorType] = ac.detectorTypeToDetectorInfo[key]
	}
	return true
}
