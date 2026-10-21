package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestDetectorParsing(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []DetectorID
	}{
		"all":                       {"AlL", allDetectors()},
		"trailing range":            {"0-", allDetectors()},
		"all after 1":               {"1-", allDetectors()[1:]},
		"named and valid range":     {"aWs,8-9", []DetectorID{{ID: detector_typepb.DetectorType_AWS}, {ID: detector_typepb.DetectorType_Github}, {ID: detector_typepb.DetectorType_Gitlab}}},
		"duplicate order preserved": {"9, 8, 9", []DetectorID{{ID: 9}, {ID: 8}}},
		"named range":               {"github - gitlab", []DetectorID{{ID: detector_typepb.DetectorType_Github}, {ID: detector_typepb.DetectorType_Gitlab}}},
		"range preserved":           {"8-9, 7-10", []DetectorID{{ID: 8}, {ID: 9}, {ID: 7}, {ID: 10}}},
		"reverse range":             {"9-8", []DetectorID{{ID: 9}, {ID: 8}}},
		"range preserved with all":  {"10-,all", append(allDetectors()[10:], allDetectors()[:10]...)},
		"empty list item":           {"8, ,9", []DetectorID{{ID: 8}, {ID: 9}}},
		"invalid end range":         {"0-1337", nil},
		"invalid name":              {"foo", nil},
		"negative":                  {"-1", nil},
		"github.v1":                 {"github.v1", []DetectorID{{ID: detector_typepb.DetectorType_Github, Version: 1}}},
		"gitlab.v100":               {"gitlab.v100", []DetectorID{{ID: detector_typepb.DetectorType_Gitlab, Version: 100}}},
		"range with versions":       {"github.v2 - gitlab.v1", nil},
		"invalid version no v":      {"gitlab.2", nil},
		"invalid version no number": {"gitlab.github", nil},
		"capital V is fine":         {"GiTlAb.V2", []DetectorID{{ID: detector_typepb.DetectorType_Gitlab, Version: 2}}},
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

func TestParseVerifierEndpointsScheme(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{url: "https://sonar.example.com"},
		{url: "http://localhost:9000"},
		{url: "http://127.0.0.1:9000"},
		{url: "http://[::1]:9000"},
		{url: "http://sonar.example.com", wantErr: true},
		{url: "http://localhost.evil.com", wantErr: true},
		{url: "http://10.0.0.5:9000", wantErr: true},
		{url: "ftp://localhost", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			_, err := ParseVerifierEndpoints(map[string]string{"SonarQube": test.url})
			if (err != nil) != test.wantErr {
				t.Errorf("url %q: got err %v, wantErr %v", test.url, err, test.wantErr)
			}
		})
	}
}
