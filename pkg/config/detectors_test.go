package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	dpb "github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestDetectorParsing(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []DetectorID
	}{
		"all":                       {"AlL", allDetectors()},
		"trailing range":            {"0-", allDetectors()},
		"all after 1":               {"1-", allDetectors()[1:]},
		"named and valid range":     {"aWs,8-9", []DetectorID{{ID: dpb.DetectorType_AWS}, {ID: dpb.DetectorType_Github}, {ID: dpb.DetectorType_Gitlab}}},
		"duplicate order preserved": {"9, 8, 9", []DetectorID{{ID: 9}, {ID: 8}}},
		"named range":               {"github - gitlab", []DetectorID{{ID: dpb.DetectorType_Github}, {ID: dpb.DetectorType_Gitlab}}},
		"range preserved":           {"8-9, 7-10", []DetectorID{{ID: 8}, {ID: 9}, {ID: 7}, {ID: 10}}},
		"reverse range":             {"9-8", []DetectorID{{ID: 9}, {ID: 8}}},
		"range preserved with all":  {"10-,all", append(allDetectors()[10:], allDetectors()[:10]...)},
		"empty list item":           {"8, ,9", []DetectorID{{ID: 8}, {ID: 9}}},
		"invalid end range":         {"0-1337", nil},
		"invalid name":              {"foo", nil},
		"negative":                  {"-1", nil},
		"github.v1":                 {"github.v1", []DetectorID{{ID: dpb.DetectorType_Github, Version: 1}}},
		"gitlab.v100":               {"gitlab.v100", []DetectorID{{ID: dpb.DetectorType_Gitlab, Version: 100}}},
		"range with versions":       {"github.v2 - gitlab.v1", nil},
		"invalid version no v":      {"gitlab.2", nil},
		"invalid version no number": {"gitlab.github", nil},
		"capital V is fine":         {"GiTlAb.V2", []DetectorID{{ID: dpb.DetectorType_Gitlab, Version: 2}}},
		"id number with version":    {"8.v2", []DetectorID{{ID: 8, Version: 2}}},
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
