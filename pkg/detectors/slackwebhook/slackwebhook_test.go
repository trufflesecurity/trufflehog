package slackwebhook

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
	validPattern   = "https://hooks.slack.com/services/TAGGINGEXAMPLE/BASE/91nziTEEzAAcaNZiz1mPPoXyS"
	invalidPattern = "https://hooks.slack.com/apps/LAGGINGEXAMPLE/BASE/91nziTEEzAAcaNZiz1mPPoXyS"
)

func TestSlackWebHook_Pattern(t *testing.T) {
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
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  nil,
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

func TestSlackWebhook_InvalidTokenVerification(t *testing.T) {
	tests := []struct {
		name                string
		statusCode          int
		body                string
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:                "invalid_token is determinate not-live",
			statusCode:          http.StatusBadRequest,
			body:                "invalid_token",
			wantVerified:        false,
			wantVerificationErr: false,
		},
		{
			name:                "invalid_token substring is determinate not-live",
			statusCode:          http.StatusBadRequest,
			body:                "error: invalid_token for webhook",
			wantVerified:        false,
			wantVerificationErr: false,
		},
		{
			name:                "unexpected 400 remains indeterminate",
			statusCode:          http.StatusBadRequest,
			body:                "something_else",
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "invalid_payload is verified",
			statusCode:          http.StatusBadRequest,
			body:                "invalid_payload",
			wantVerified:        true,
			wantVerificationErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{client: common.ConstantResponseHttpClient(tt.statusCode, tt.body)}
			got, err := s.FromData(context.Background(), true, []byte(validPattern))
			if err != nil {
				t.Fatalf("FromData error: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 result, got %d", len(got))
			}
			if got[0].Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", got[0].Verified, tt.wantVerified)
			}
			if (got[0].VerificationError() != nil) != tt.wantVerificationErr {
				t.Errorf("VerificationError = %v, wantVerificationErr %v", got[0].VerificationError(), tt.wantVerificationErr)
			}
		})
	}
}
