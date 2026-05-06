package grafanaserviceaccount

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKey     = "glsa_0123456789ABCDEFGHIJKLMNOPQRSTUV_a1b2c3d4"
	validDomain  = "1VV04Zn7iJ0B8w2nBWqG5rB-dVUL3ELSE0zMqnMHjWp-AecPbpdwSde.grafana.net"
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "GrafanaServiceAccount",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"grafana_secret": "` + validKey + `",
			"domain: "` + validDomain + `"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = validDomain + ":" + validKey
)

func TestGrafanaServiceAccount_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{secret},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func TestVerifyGrafanaServiceAccountStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantValid  bool
		wantErr    bool
	}{
		{
			name:       "ok verifies token",
			statusCode: http.StatusOK,
			wantValid:  true,
		},
		{
			name:       "unauthorized rejects token",
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "forbidden verifies token",
			statusCode: http.StatusForbidden,
			wantValid:  true,
		},
		{
			name:       "unexpected status returns error",
			statusCode: http.StatusNotFound,
			wantErr:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotValid, err := verifyGrafanaServiceAccount(
				context.Background(),
				common.ConstantResponseHttpClient(test.statusCode, ""),
				validDomain,
				validKey,
			)

			if gotValid != test.wantValid {
				t.Fatalf("valid = %v, want %v", gotValid, test.wantValid)
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestGrafanaServiceAccount_DefaultClientBlocksLocalAddresses(t *testing.T) {
	if defaultClient != detectors.DetectorHttpClientWithNoLocalAddresses {
		t.Fatal("default client must block local addresses because verification URLs are built from extracted domains")
	}
}
