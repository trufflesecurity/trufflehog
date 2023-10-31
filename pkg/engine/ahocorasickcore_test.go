package engine

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

func (d testDetectorV1) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (d testDetectorV1) Keywords() []string {
	return []string{"a"}
}

func (d testDetectorV1) Type() detectorspb.DetectorType {
	return TestDetectorType
}

func (d testDetectorV1) Version() int {
	return 1
}

type testDetectorV2 struct {
}

func (d testDetectorV2) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (d testDetectorV2) Keywords() []string {
	return []string{"b"}
}

func (d testDetectorV2) Type() detectorspb.DetectorType {
	return TestDetectorType
}

func (d testDetectorV2) Version() int {
	return 2
}

var _ detectors.Detector = (*testDetectorV1)(nil)
var _ detectors.Detector = (*testDetectorV2)(nil)
var _ detectors.Versioner = (*testDetectorV1)(nil)
var _ detectors.Versioner = (*testDetectorV2)(nil)

func TestAhoCorasickCore_MultipleCustomDetectorsMatchable(t *testing.T) {
	customDetector1, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 1",
		Keywords: []string{"a"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	customDetector2, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 2",
		Keywords: []string{"b"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	testCases := []struct {
		matchString string
		detector    detectors.Detector
	}{
		{
			matchString: "a",
			detector:    customDetector1,
		},
		{
			matchString: "b",
			detector:    customDetector2,
		},
	}

	var allDetectors []detectors.Detector
	for _, tt := range testCases {
		allDetectors = append(allDetectors, tt.detector)
	}

	ac := NewAhoCorasickCore(allDetectors)

	for _, tt := range testCases {
		matches := ac.MatchString(tt.matchString)
		assert.Equal(t, 1, len(matches))

		matchingDetectors := make(map[detectorspb.DetectorType]detectors.Detector)
		ac.PopulateDetectorsByMatch(matches[0], matchingDetectors)
		assert.Equal(t, 1, len(matchingDetectors))
		assert.Equal(t, tt.detector, matchingDetectors[detectorspb.DetectorType_CustomRegex])
	}
}

func TestAhoCorasickCore_MultipleDetectorVersionsMatchable(t *testing.T) {
	testCases := []struct {
		matchString string
		detector    detectors.Detector
	}{
		{
			matchString: "a",
			detector:    testDetectorV1{},
		},
		{
			matchString: "b",
			detector:    testDetectorV2{},
		},
	}

	var allDetectors []detectors.Detector
	for _, tt := range testCases {
		allDetectors = append(allDetectors, tt.detector)
	}

	ac := NewAhoCorasickCore(allDetectors)

	for _, tt := range testCases {
		matches := ac.MatchString(tt.matchString)
		assert.Equal(t, 1, len(matches))

		matchingDetectors := make(map[detectorspb.DetectorType]detectors.Detector)
		ac.PopulateDetectorsByMatch(matches[0], matchingDetectors)
		assert.Equal(t, 1, len(matchingDetectors))
		assert.Equal(t, tt.detector, matchingDetectors[TestDetectorType])
	}
}
