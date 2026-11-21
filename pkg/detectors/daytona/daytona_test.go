package daytona

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Synthetic secret in the exact shape Daytona issues. Not a real credential.
var validKey = "dtn_" + strings.Repeat("0123456789abcdef", 4)

func TestDaytona_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: "daytona_token = '" + validKey + "'",
			want:  []string{validKey},
		},
		{
			name:  "invalid pattern - 63 hex chars",
			input: "daytona_token = 'dtn_" + strings.Repeat("0123456789abcdef", 3) + "0123456789abcde'",
			want:  nil,
		},
		{
			name:  "invalid pattern - 65 hex chars",
			input: "daytona_token = 'dtn_" + strings.Repeat("0123456789abcdef", 4) + "0'",
			want:  nil,
		},
		{
			name:  "invalid pattern - uppercase hex",
			input: "daytona_token = 'dtn_" + strings.Repeat("0123456789ABCDEF", 4) + "'",
			want:  nil,
		},
		{
			name:  "invalid pattern - wrong prefix",
			input: "daytona keys start with dtn_, this one does not: 'dta_" + strings.Repeat("0123456789abcdef", 4) + "'",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
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

func TestDaytona_Verify(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		wantVerified bool
		wantErr      bool
	}{
		{name: "200 verified", status: http.StatusOK, wantVerified: true},
		{name: "401 determinately invalid", status: http.StatusUnauthorized},
		{name: "500 indeterminate", status: http.StatusInternalServerError, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/sandbox" {
					t.Errorf("unexpected request %s %s, want GET /api/sandbox", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer "+validKey {
					t.Errorf("Authorization = %q, want %q", got, "Bearer "+validKey)
				}
				w.WriteHeader(test.status)
			}))
			defer ts.Close()

			d := Scanner{client: ts.Client(), endpoint: ts.URL + "/api/sandbox"}
			results, err := d.FromData(context.Background(), true, []byte("daytona_token = '"+validKey+"'"))
			if err != nil {
				t.Fatalf("FromData: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			r := results[0]
			if r.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, test.wantVerified)
			}
			if got := r.ExtraData["rotation_guide"]; got != "https://www.daytona.io/docs/api-keys/" {
				t.Errorf("ExtraData[rotation_guide] = %q, want the Daytona rotation guide URL", got)
			}
			if (r.VerificationError() != nil) != test.wantErr {
				t.Errorf("VerificationError = %v, wantErr = %v", r.VerificationError(), test.wantErr)
			}
		})
	}
}
