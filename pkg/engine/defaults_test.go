package engine

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestDefaultDetectorsHaveUniqueVersions(t *testing.T) {
	detectorTypeToVersions := make(map[detectorspb.DetectorType]map[int]struct{})
	addVersion := func(versions map[int]struct{}, version int) map[int]struct{} {
		if versions == nil {
			versions = make(map[int]struct{})
		}
		versions[version] = struct{}{}
		return versions
	}
	// Loop through all our default detectors and find the ones that
	// implement Versioner. Of those, check each version number is unique.
	for _, detector := range DefaultDetectors() {
		v, ok := detector.(detectors.Versioner)
		if !ok {
			continue
		}
		version := v.Version()
		key := detector.Type()
		if set, ok := detectorTypeToVersions[key]; ok && set != nil {
			if _, ok := set[version]; ok {
				t.Errorf("detector %q has duplicate version: %d", detectorspb.DetectorType_name[int32(key)], version)
			}
		}
		detectorTypeToVersions[key] = addVersion(detectorTypeToVersions[key], version)
	}
}

func TestDefaultDetectorTypesImplementing(t *testing.T) {
	isVersioner := DefaultDetectorTypesImplementing[detectors.Versioner]()
	for _, detector := range DefaultDetectors() {
		_, expectedOk := detector.(detectors.Versioner)
		_, gotOk := isVersioner[detector.Type()]
		if expectedOk == gotOk {
			continue
		}
		t.Errorf(
			"detector %q doesn't match expected",
			detectorspb.DetectorType_name[int32(detector.Type())],
		)
	}
}
