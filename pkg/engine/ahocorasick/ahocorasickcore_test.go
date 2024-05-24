package ahocorasick

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const TestDetectorType = -1

type testDetectorV1 struct {
}

func (testDetectorV1) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV1) Keywords() []string { return []string{"a", "b"} }

func (testDetectorV1) Type() detectorspb.DetectorType {
	return TestDetectorType
}

func (testDetectorV1) Version() int { return 1 }

type testDetectorV2 struct {
}

func (testDetectorV2) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV2) Keywords() []string {
	return []string{"a"}
}

func (testDetectorV2) Type() detectorspb.DetectorType {
	return TestDetectorType
}

func (testDetectorV2) Version() int { return 2 }

type testDetectorV3 struct {
}

func (testDetectorV3) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV3) Keywords() []string {
	return []string{"truffle"}
}

func (testDetectorV3) Type() detectorspb.DetectorType {
	return TestDetectorType
}

func (testDetectorV3) Version() int { return 1 }

var _ detectors.Detector = (*testDetectorV1)(nil)
var _ detectors.Detector = (*testDetectorV2)(nil)
var _ detectors.Versioner = (*testDetectorV1)(nil)
var _ detectors.Versioner = (*testDetectorV2)(nil)
var _ detectors.Versioner = (*testDetectorV3)(nil)

func TestAhoCorasickCore_MultipleCustomDetectorsMatchable(t *testing.T) {
	customDetector1, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 1",
		Keywords: []string{"a"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	customDetector2, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 2",
		Keywords: []string{"a"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	allDetectors := []detectors.Detector{customDetector1, customDetector2}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestAhoCorasickCore_MultipleDetectorVersionsMatchable(t *testing.T) {
	v1 := testDetectorV1{}
	v2 := testDetectorV2{}
	allDetectors := []detectors.Detector{v1, v2}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestAhoCorasickCore_NoDuplicateDetectorsMatched(t *testing.T) {
	d := testDetectorV1{}
	allDetectors := []detectors.Detector{d}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a a b b"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestFindDetectorMatches(t *testing.T) {
	testCases := []struct {
		name           string
		detectors      []detectors.Detector
		sampleData     string
		expectedResult map[DetectorKey][][]int64
	}{

		{
			name: "single matchSpan",
			detectors: []detectors.Detector{
				testDetectorV3{},
			},
			sampleData: "This is a sample data containing keyword truffle",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV3{}): {{41, 48}},
			},
		},
		{
			name: "Multiple matches overlapping",
			detectors: []detectors.Detector{
				testDetectorV1{},
			},
			sampleData: "This is a sample data containing keyword a",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV1{}): {{8, 42}},
			},
		},
		{
			name: "Multiple matches",
			detectors: []detectors.Detector{
				testDetectorV2{},
			},
			sampleData: `This is the first occurrence of the letter a.
                 Lorem ipsum dolor sit met, consectetur dipiscing elit. Sed uctor,
                 mgn bibendum bibendum, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. Donec
                 sed ugue. Sed euismod, ugue sit met liqum lcini,
                 ugue ugue tincidunt ugue, eget ultricies ugue ugue id
                 ugue. Meens liquet libero c libero molestie, nec
                 mlesud ugue ugue eget. Donec sed ugue. Sed euismod,
                 ugue sit met liqum lcini, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. This is the second occurrence of the letter a.`,
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV2{}): {{43, 555}, {854, 856}},
			},
		},
		{
			name: "No matches",
			detectors: []detectors.Detector{
				testDetectorV1{},
				testDetectorV2{},
			},
			sampleData:     "xxy yzz lnnope",
			expectedResult: map[DetectorKey][][]int64{},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ac := NewAhoCorasickCore(tc.detectors)
			detectorMatches := ac.FindDetectorMatches([]byte(tc.sampleData))

			// Verify that all matching detectors and their matches are returned.
			for _, detectorMatch := range detectorMatches {
				assert.Contains(t, tc.expectedResult, detectorMatch.Key, "Expected detector key to be present")

				expectedMatches := tc.expectedResult[detectorMatch.Key]
				actualMatches := make([][]int64, len(detectorMatch.matchSpans))
				for i, match := range detectorMatch.matchSpans {
					actualMatches[i] = []int64{match.startOffset, match.endOffset}
				}

				assert.ElementsMatch(t, expectedMatches, actualMatches, "Expected matches to be returned for the detector")
			}

			// Verify that all expected matches are returned for each detector.
			for key, expectedMatches := range tc.expectedResult {
				var actualMatches [][]int64
				for _, detectorMatch := range detectorMatches {
					if detectorMatch.Key == key {
						for _, match := range detectorMatch.matchSpans {
							actualMatches = append(actualMatches, []int64{match.startOffset, match.endOffset})
						}
					}
				}
				assert.ElementsMatch(t, expectedMatches, actualMatches, "Expected all matches to be returned for the detector")
			}
		})
	}
}
