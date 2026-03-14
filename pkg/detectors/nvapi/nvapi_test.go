package nvapi

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestNvapi_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "nvapi_token = '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'",
			want:  []string{"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"},
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

func TestNvapi_Verification(t *testing.T) {
	validToken := "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"

	// Mock response with multiple roles containing duplicate orgs and roles
	mockResponse := `{
		"type": "PERSONAL_KEY",
		"user": {
			"name": "testuser@example.com",
			"email": "testuser@example.com",
			"roles": [
				{
					"org": {"displayName": "Test-Org"},
					"orgRoles": ["ROLE_A", "ROLE_B", "ROLE_C"]
				},
				{
					"org": {"displayName": "Test-Org"},
					"orgRoles": ["ROLE_A", "ROLE_B", "ROLE_D"]
				},
				{
					"org": {"displayName": "Another-Org"},
					"orgRoles": ["ROLE_C", "ROLE_E"]
				}
			]
		}
	}`

	tests := []struct {
		name    string
		s       Scanner
		input   string
		verify  bool
		want    []detectors.Result
		wantErr bool
	}{
		{
			name:   "found, verified with extraData",
			s:      Scanner{client: common.ConstantResponseHttpClient(200, mockResponse)},
			input:  "nvapi_token = '" + validToken + "'",
			verify: true,
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NVAPI,
					Verified:     true,
					ExtraData: map[string]string{
						"type":              "PERSONAL_KEY",
						"user_name":         "testuser@example.com",
						"user_email":        "testuser@example.com",
						"org_display_names": "Test-Org, Another-Org",
						"org_roles":         "ROLE_A, ROLE_B, ROLE_C, ROLE_D, ROLE_E",
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "found, unverified (401)",
			s:      Scanner{client: common.ConstantResponseHttpClient(401, "")},
			input:  "nvapi_token = '" + validToken + "'",
			verify: true,
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NVAPI,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name:   "found, no verification",
			s:      Scanner{},
			input:  "nvapi_token = '" + validToken + "'",
			verify: false,
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NVAPI,
					Verified:     false,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(context.Background(), tt.verify, []byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("Scanner.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("Scanner.FromData() got %d results, want %d", len(got), len(tt.want))
				return
			}

			// For ExtraData comparison, we need to check that all expected keys exist
			// with the correct values, but the order of comma-separated values may vary
			for i := range got {
				if got[i].Verified != tt.want[i].Verified {
					t.Errorf("Verified = %v, want %v", got[i].Verified, tt.want[i].Verified)
				}
				if got[i].DetectorType != tt.want[i].DetectorType {
					t.Errorf("DetectorType = %v, want %v", got[i].DetectorType, tt.want[i].DetectorType)
				}

				if tt.want[i].ExtraData != nil {
					if got[i].ExtraData == nil {
						t.Errorf("ExtraData is nil, want %v", tt.want[i].ExtraData)
						continue
					}

					// Check non-list fields exactly
					for _, key := range []string{"type", "user_name", "user_email"} {
						if got[i].ExtraData[key] != tt.want[i].ExtraData[key] {
							t.Errorf("ExtraData[%s] = %v, want %v", key, got[i].ExtraData[key], tt.want[i].ExtraData[key])
						}
					}

					// Check that org_display_names and org_roles contain all expected values (order may vary)
					for _, key := range []string{"org_display_names", "org_roles"} {
						gotValues := parseCommaSeparated(got[i].ExtraData[key])
						wantValues := parseCommaSeparated(tt.want[i].ExtraData[key])
						if diff := cmp.Diff(wantValues, gotValues, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
							t.Errorf("ExtraData[%s] diff: (-want +got)\n%s", key, diff)
						}
					}
				}
			}
		})
	}
}

func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, v := range splitAndTrim(s, ",") {
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}

func splitAndTrim(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, trim(s[start:i]))
			start = i + len(sep)
		}
	}
	result = append(result, trim(s[start:]))
	return result
}

func trim(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}
