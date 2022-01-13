package engine

import (
	"github.com/trufflesecurity/trufflehog/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/pkg/detectors/testdetector"
)

func DefaultDetectors() []detectors.Detector {
	return []detectors.Detector{
		&testdetector.Detector{},
	}
}
