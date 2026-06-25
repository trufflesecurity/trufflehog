package msg91

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestMSG91_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - assignment",
			input: `MSG91_AUTHKEY=428156BpxVtJ7DLAZP79gg1be1Q2`,
			want:  []string{"428156BpxVtJ7DLAZP79gg1be1Q2"},
		},
		{
			name:  "valid pattern - quoted",
			input: `msg91_api_key: "892341CqyWuK8EMBBQ80hh2cf2R3"`,
			want:  []string{"892341CqyWuK8EMBBQ80hh2cf2R3"},
		},
		{
			name:  "invalid pattern - no keyword",
			input: `AUTHKEY=428156BpxVtJ7DLAZP79gg1be1Q2`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too short",
			input: `msg91 authkey = 428156BpxVtJ7DLAZP79`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too long",
			input: `msg91 authkey = 428156BpxVtJ7DLAZP79gg1be1Q2XXXXXXXX`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && test.want != nil {
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

// TestMSG91_Verification exercises the verification logic using mock HTTP
// clients, so it requires no live credentials.
func TestMSG91_Verification(t *testing.T) {
	const token = "428156BpxVtJ7DLAZP79gg1be1Q2"
	input := []byte("msg91 authkey = " + token)

	tests := []struct {
		name                string
		client              *http.Client
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:         "verified (200 + balance body)",
			client:       common.ConstantResponseHttpClient(http.StatusOK, `{"SMS":"0.19","VOICE":"0.00"}`),
			wantVerified: true,
		},
		{
			name:         "unverified - determinate (200 + invalid authkey body)",
			client:       common.ConstantResponseHttpClient(http.StatusOK, "Invalid authkey"),
			wantVerified: false,
		},
		{
			name:         "unverified - determinate (401)",
			client:       common.ConstantResponseHttpClient(http.StatusUnauthorized, ""),
			wantVerified: false,
		},
		{
			name:                "unverified - indeterminate (unexpected response)",
			client:              common.ConstantResponseHttpClient(http.StatusInternalServerError, ""),
			wantVerified:        false,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: test.client}
			results, err := s.FromData(context.Background(), true, input)
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			r := results[0]
			if r.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, test.wantVerified)
			}
			if (r.VerificationError() != nil) != test.wantVerificationErr {
				t.Errorf("VerificationError = %v, wantVerificationErr %v", r.VerificationError(), test.wantVerificationErr)
			}
		})
	}
}

// TestMSG91_Verification_Timeout covers the indeterminate failure caused by a
// network timeout. The 1ms client deadline elapses before the request to the
// MSG91 API can complete, so verification must surface an indeterminate error.
func TestMSG91_Verification_Timeout(t *testing.T) {
	s := Scanner{client: common.SaneHttpClientTimeOut(1 * time.Millisecond)}

	results, err := s.FromData(context.Background(), true, []byte("msg91 authkey = 428156BpxVtJ7DLAZP79gg1be1Q2"))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Errorf("expected unverified on timeout")
	}
	if results[0].VerificationError() == nil {
		t.Errorf("expected indeterminate verification error on timeout")
	}
}
