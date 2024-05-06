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

// GetDetectorByKey returns the detector associated with the given key. If no detector is found, it
// returns nil.
func (ac *AhoCorasickCore) GetDetectorByKey(key DetectorKey) detectors.Detector {
	return ac.detectorsByKey[key]
}

// DetectorInfo represents a detected pattern's metadata in a data chunk.
// It encapsulates the key identifying a specific detector and the detector instance itself.
type DetectorInfo struct {
	Key DetectorKey
	detectors.Detector
}

// PopulateMatchingDetectors populates the given detector slice with all the detectors matching the
// provided input. This method populates an existing map rather than allocating a new one because
// it will be called once per chunk and that many allocations has a noticeable performance cost.
// It returns a slice of unique 'DetectorInfo' corresponding to the matched detectors. This slice is
// constructed to prevent duplications by utilizing an internal map to track already processed detectors.
func (ac *AhoCorasickCore) PopulateMatchingDetectors(chunkData string, dts map[DetectorKey]detectors.Detector) []DetectorInfo {
	matches := ac.prefilter.MatchString(strings.ToLower(chunkData))

	// Use a map to avoid adding duplicate detectors to the slice.
	addedDetectors := make(map[DetectorKey]struct{})
	uniqueDetectors := make([]DetectorInfo, 0, len(matches))

	for _, m := range matches {
		for _, k := range ac.keywordsToDetectors[m.MatchString()] {
			if _, exists := addedDetectors[k]; exists {
				continue
			}
			// Add to the map to track already added detectors.
			addedDetectors[k] = struct{}{}

			// Add the detector to the map and slice.
			detector := ac.detectorsByKey[k]
			dts[k] = detector
			uniqueDetectors = append(uniqueDetectors, DetectorInfo{Key: k, Detector: detector})
		}
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
