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

func (d testDetectorV1) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (d testDetectorV1) Keywords() []string {
	return []string{"a", "b"}
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
	return []string{"a"}
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
		Keywords: []string{"a"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	allDetectors := []detectors.Detector{customDetector1, customDetector2}

	ac := NewAhoCorasickCore(allDetectors)

	detectorsMap := make(map[DetectorKey]detectors.Detector, 2)
	ac.PopulateMatchingDetectors("a", detectorsMap)
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range detectorsMap {
		matchingDetectors = append(matchingDetectors, d)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestAhoCorasickCore_MultipleDetectorVersionsMatchable(t *testing.T) {
	v1 := testDetectorV1{}
	v2 := testDetectorV2{}
	allDetectors := []detectors.Detector{v1, v2}

	ac := NewAhoCorasickCore(allDetectors)

	detectorsMap := make(map[DetectorKey]detectors.Detector, 2)
	ac.PopulateMatchingDetectors("a", detectorsMap)
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range detectorsMap {
		matchingDetectors = append(matchingDetectors, d)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestAhoCorasickCore_NoDuplicateDetectorsMatched(t *testing.T) {
	d := testDetectorV1{}
	allDetectors := []detectors.Detector{d}

	ac := NewAhoCorasickCore(allDetectors)

	detectorsMap := make(map[DetectorKey]detectors.Detector, 2)
	ac.PopulateMatchingDetectors("a a b b", detectorsMap)
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range detectorsMap {
		matchingDetectors = append(matchingDetectors, d)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}
