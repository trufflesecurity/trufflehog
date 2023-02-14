package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	dpb "github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestDetectorParsing(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []dpb.DetectorType
	}{
		"all":                       {"AlL", allDetectors()},
		"trailing range":            {"0-", allDetectors()},
		"all after 1":               {"1-", allDetectors()[1:]},
		"named and valid range":     {"aWs,8-9", []dpb.DetectorType{dpb.DetectorType_AWS, dpb.DetectorType_Github, dpb.DetectorType_Gitlab}},
		"duplicate order preserved": {"9, 8, 9", []dpb.DetectorType{9, 8}},
		"named range":               {"github - gitlab", []dpb.DetectorType{dpb.DetectorType_Github, dpb.DetectorType_Gitlab}},
		"range preserved":           {"8-9, 7-10", []dpb.DetectorType{8, 9, 7, 10}},
		"reverse range":             {"9-8", []dpb.DetectorType{9, 8}},
		"range preserved with all":  {"10-,all", append(allDetectors()[10:], allDetectors()[:10]...)},
		"empty list item":           {"8, ,9", []dpb.DetectorType{8, 9}},
		"invalid end range":         {"0-1337", nil},
		"invalid name":              {"foo", nil},
		"negative":                  {"-1", nil},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, gotErr := ParseDetectors(tt.input)
			if tt.expected == nil {
				assert.Error(t, gotErr)
				return
			}
			assert.Equal(t, tt.expected, got)
		})
	}
}
