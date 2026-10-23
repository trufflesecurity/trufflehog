package runpod

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestRunpod_VerifyMatch(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantVerified bool
		wantExtra    map[string]string
		wantErr      bool
	}{
		{
			name:         "200 OK is verified",
			statusCode:   http.StatusOK,
			wantVerified: true,
			wantExtra:    nil,
			wantErr:      false,
		},
		{
			name:         "403 Forbidden is verified with restricted scope",
			statusCode:   http.StatusForbidden,
			wantVerified: true,
			wantExtra:    map[string]string{"scope": "restricted"},
			wantErr:      false,
		},
		{
			name:         "401 Unauthorized is unverified",
			statusCode:   http.StatusUnauthorized,
			wantVerified: false,
			wantExtra:    nil,
			wantErr:      false,
		},
		{
			name:         "500 InternalServerError is error (indeterminate)",
			statusCode:   http.StatusInternalServerError,
			wantVerified: false,
			wantExtra:    nil,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := common.ConstantResponseHttpClient(tt.statusCode, "")
			verified, extra, err := verifyMatch(context.Background(), client, "rpa_test123456789012345678901234567890")
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyMatch() error = %v, wantErr %v", err, tt.wantErr)
			}
			if verified != tt.wantVerified {
				t.Errorf("verifyMatch() verified = %v, want %v", verified, tt.wantVerified)
			}
			if diff := cmp.Diff(tt.wantExtra, extra); diff != "" {
				t.Errorf("verifyMatch() extra diff: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestRunpod_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid scoped token pattern",
			input: "runpod_api_key = 'rpa_vL2M3N4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0F'",
			want:  []string{"rpa_vL2M3N4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0F"},
		},
		{
			name:  "valid contextual legacy token",
			input: "export RUNPOD_API_KEY=\"2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D1234567890\"",
			want:  []string{"2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D1234567890"},
		},
		{
			name: "finds multiple matches",
			input: `
				RUNPOD_API_KEY=rpa_vL2M3N4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0F
				runpod_token = "2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D1234567890"
			`,
			want: []string{
				"rpa_vL2M3N4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0F",
				"2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D1234567890",
			},
		},
		{
			name:  "invalid pattern without keyword",
			input: "random_token = '2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D1234567890'",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(detectorMatches) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.Raw)] = struct{}{}
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
