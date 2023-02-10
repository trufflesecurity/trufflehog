package engine

import (
	"fmt"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// Detectors only returns a specific set of detectors if they are specified in the
// detectors list and are valid. Otherwise, it returns the default set of detectors.
func Detectors(ctx context.Context, dts []string) ([]detectors.Detector, error) {
	configured := setDetectors(ctx, dts)

	if len(configured) == 0 {
		return nil, fmt.Errorf("no detectors specified")
	}

	ds := filterDetectors(dts, configured)
	if len(ds) != len(configured) {
		return nil, fmt.Errorf("1 or more detectors are invalid, please check your detector types")
	}
	return ds, nil
}

func setDetectors(ctx context.Context, dts []string) map[string]struct{} {
	valid := make(map[string]struct{}, len(dts))
	for _, d := range dts {
		ctx.Logger().Info("setting detector", "detector-name", d)
		valid[strings.ToLower(d)] = struct{}{}
	}

	return valid
}

func filterDetectors(dts []string, configured map[string]struct{}) []detectors.Detector {
	ds := make([]detectors.Detector, 0, len(dts))
	for _, d := range DefaultDetectors() {
		if _, ok := configured[strings.ToLower(d.Type().String())]; ok {
			ds = append(ds, d)
		}
	}

	return ds
}
