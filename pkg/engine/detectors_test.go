package engine

import (
	"reflect"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure"
)

func TestNewDectorsConfig(t *testing.T) {
	tests := []struct {
		name     string
		inc      string
		exc      string
		expected DetectorFilter
		wantErr  bool
	}{
		{
			name:    "No dts specified, returns error",
			inc:     "",
			exc:     "",
			wantErr: true,
		},
		{
			name:     "Include dts specified, returns config with include",
			inc:      "AWS",
			expected: &IncludeDetectorFilter{includeDetectors: []string{"AWS"}},
		},
		{
			name:     "Exclude dts specified, returns config with exclude",
			exc:      "AWS",
			expected: &ExcludeDetectorFilter{excludeDetectors: []string{"AWS"}},
		},
		{
			name:    "Include and exclude dts specified, returns error",
			inc:     "AWS",
			exc:     "Azure",
			wantErr: true,
		},
	}

	for _, test := range tests {
		result, err := NewDetectorsConfig(test.inc, test.exc)
		if err != nil && !test.wantErr {
			t.Errorf("NewDetectorsConfig(%v, %v) got %v, want %v", test.inc, test.exc, err, test.expected)
		}

		if result != nil {
			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("NewDetectorsConfig(%v, %v) got %v, want %v", test.inc, test.exc, result, test.expected)
			}
		}
	}
}

func TestDetectors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		dt       DetectorFilter
		expected []detectors.Detector
		wantErr  bool
	}{
		{
			name:    "No dts specified, returns default set",
			dt:      &IncludeDetectorFilter{},
			wantErr: true,
		},
		{
			name:     "Valid include detectors (1) specified, returns valid set",
			dt:       &IncludeDetectorFilter{includeDetectors: []string{"AWS"}},
			expected: []detectors.Detector{aws.New()},
		},
		{
			name:     "Valid include detectors (2) specified, returns valid set",
			dt:       &IncludeDetectorFilter{includeDetectors: []string{"AWS", "Azure"}},
			expected: []detectors.Detector{aws.New(), &azure.Scanner{}},
		},
		{
			name:    "Invalid include detectors specified, returns error",
			dt:      &IncludeDetectorFilter{includeDetectors: []string{"AWS", "Azure", "Invalid"}},
			wantErr: true,
		},
		{
			name:     "Valid exlude detectors (1) specified, returns valid set",
			dt:       &ExcludeDetectorFilter{excludeDetectors: []string{"AWS"}},
			expected: excludeDetectors(map[string]struct{}{"aws": {}}),
		},
		{
			name:     "Valid exclude detectors (2) specified, returns valid set",
			dt:       &ExcludeDetectorFilter{excludeDetectors: []string{"AWS", "Azure"}},
			expected: excludeDetectors(map[string]struct{}{"aws": {}, "azure": {}}),
		},
		{
			name:    "Invalid exclude detector specified, returns error",
			dt:      &ExcludeDetectorFilter{excludeDetectors: []string{"AWS", "Azure", "Invalid"}},
			wantErr: true,
		},
	}

	for _, test := range tests {
		result, err := Detectors(ctx, test.dt)
		if err != nil && !test.wantErr {
			t.Errorf("Detectors(%v) got %v, want %v", test.dt, err, test.expected)
		}

		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("Detectors(%v) got %v, want %v", test.dt, result, test.expected)
		}
	}
}

func excludeDetectors(exclude map[string]struct{}) []detectors.Detector {
	defaultDetectors := DefaultDetectors()
	result := make([]detectors.Detector, 0, len(defaultDetectors)-len(exclude))
	for _, detector := range defaultDetectors {
		if _, ok := exclude[strings.ToLower(detector.Type().String())]; !ok {
			result = append(result, detector)
		}
	}
	return result
}
