package engine

import (
	"fmt"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// DetectorFilter allows for include/exclude detectors.
type DetectorFilter interface {
	detectors() []string
	filter(map[string]struct{}) ([]detectors.Detector, error)
}

// IncludeDetectorFilter is a detector filter that only includes the specified detectors.
type IncludeDetectorFilter struct {
	includeDetectors []string
}

func (i *IncludeDetectorFilter) detectors() []string {
	return i.includeDetectors
}

func (i *IncludeDetectorFilter) filter(include map[string]struct{}) ([]detectors.Detector, error) {
	ds := make([]detectors.Detector, 0, len(i.includeDetectors))
	for _, d := range DefaultDetectors() {
		if _, ok := include[strings.ToLower(d.Type().String())]; ok {
			ds = append(ds, d)
		}
	}

	if len(ds) != len(include) {
		return nil, fmt.Errorf("1 or more detectors are invalid, please check your detector types")
	}

	return ds, nil
}

// ExcludeDetectorFilter is a detector filter that excludes the specified detectors.
type ExcludeDetectorFilter struct {
	excludeDetectors []string
}

func (e *ExcludeDetectorFilter) detectors() []string {
	return e.excludeDetectors
}

func (e *ExcludeDetectorFilter) filter(exclude map[string]struct{}) ([]detectors.Detector, error) {
	defaultDetectors := DefaultDetectors()
	l := len(defaultDetectors) - len(exclude)
	result := make([]detectors.Detector, 0, l)
	for _, detector := range defaultDetectors {
		if _, ok := exclude[strings.ToLower(detector.Type().String())]; !ok {
			result = append(result, detector)
		}
	}

	if len(result) != l {
		return nil, fmt.Errorf("1 or more detectors are invalid, please check your detector types")
	}
	return result, nil
}

// NewDetectorsConfig creates a new detector filter based on the include/exclude arguments.
func NewDetectorsConfig(include, exclude string) (DetectorFilter, error) {
	if len(include) == 0 && len(exclude) == 0 {
		return nil, nil
	}

	if len(include) > 0 && len(exclude) > 0 {
		return nil, fmt.Errorf("cannot specify both include and exclude detectors")
	}

	// Determine the detector filter type.
	if len(include) > len(exclude) {
		return &IncludeDetectorFilter{includeDetectors: strings.Split(include, ",")}, nil
	}
	return &ExcludeDetectorFilter{excludeDetectors: strings.Split(exclude, ",")}, nil
}

// Detectors only returns a specific set of detectors if they are specified in the
// detector list and are valid. Otherwise, an error is returned.
func Detectors(ctx context.Context, dt DetectorFilter) ([]detectors.Detector, error) {
	if dt == nil {
		return nil, nil
	}
	configured := setDetectors(ctx, dt.detectors())

	if len(configured) == 0 {
		return nil, fmt.Errorf("no detectors specified")
	}

	return dt.filter(configured)
}

func setDetectors(ctx context.Context, dts []string) map[string]struct{} {
	valid := make(map[string]struct{}, len(dts))
	for _, d := range dts {
		ctx.Logger().Info("setting detector", "detector-name", d)
		valid[strings.ToLower(d)] = struct{}{}
	}

	return valid
}
