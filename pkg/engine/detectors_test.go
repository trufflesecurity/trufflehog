package engine

import (
	"reflect"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure"
)

func TestDetectors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		dts      []string
		expected []detectors.Detector
		wantErr  bool
	}{
		{
			name:    "No detectors specified, returns default set",
			dts:     []string{},
			wantErr: true,
		},
		{
			name:     "Valid detector (1) specified, returns valid set",
			dts:      []string{"AWS"},
			expected: []detectors.Detector{aws.New()},
		},
		{
			name:     "Valid detectors (2) specified, returns valid set",
			dts:      []string{"AWS", "Azure"},
			expected: []detectors.Detector{aws.New(), &azure.Scanner{}},
		},
		{
			name:    "Invalid detector specified, returns error",
			dts:     []string{"AWS", "InvalidType"},
			wantErr: true,
		},
	}

	for _, test := range tests {
		result, err := Detectors(ctx, test.dts)
		if err != nil && !test.wantErr {
			t.Errorf("For detectors %v, expected no error, got %v", test.dts, err)
		}

		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("For detectors %v, expected %v, got %v", test.dts, test.expected, result)
		}
	}
}
