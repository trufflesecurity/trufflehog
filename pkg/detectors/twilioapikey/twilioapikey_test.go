package twilioapikey

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validAPIKey   = "SKbddcfb88fake8f7c4d9aefake7de1fc5"
	invalidAPIKey = "SK_bddcfb88fake8f7c4d9aefake7de1fc"
	validSecret   = "k7JXtY3WBtUqthisisfakeZDqVcjZxYI"
	invalidSecret = "k6JXtY3WBtU$thisisfakeZDqVcjZxYI"
	keyword       = "twilio"
)

func TestTwilioAPIKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword twilio",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validAPIKey, keyword, validSecret),
			want:  []string{validAPIKey + validSecret},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidAPIKey, keyword, invalidSecret),
			want:  []string{},
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

func TestTwilioAPIKey_SecretRedacted(t *testing.T) {
	d := Scanner{}

	results, err := d.FromData(
		context.Background(),
		false,
		[]byte(fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validAPIKey, keyword, validSecret)))
	if err != nil {
		t.Errorf("error = %v", err)
		return
	}

	if len(results) == 0 {
		t.Errorf("did not receive result")
	}

	if results[0].Redacted != validSecret[:5]+"..." {
		t.Errorf("expected redacted secret to be '%s', got '%s'", validSecret[:5]+"...", results[0].Redacted)
	}
}
type errorTransport struct{ err error }

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

func TestTwilioAPIKey_VerificationDeterminacy(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))

	tests := []struct {
		name                string
		client              *http.Client
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:                "authenticated rejection is determinate",
			client:              common.ConstantResponseHttpClient(http.StatusUnauthorized, ""),
			wantVerified:        false,
			wantVerificationErr: false,
		},
		{
			name:                "success is determinate",
			client:              common.ConstantResponseHttpClient(http.StatusOK, `{"services":[{"friendly_name":"n","sid":"s","account_sid":"a"}]}`),
			wantVerified:        true,
			wantVerificationErr: false,
		},
		{
			name:                "rate limit is indeterminate",
			client:              common.ConstantResponseHttpClient(http.StatusTooManyRequests, ""),
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "connection reset is indeterminate",
			client:              &http.Client{Transport: errorTransport{err: errors.New("read: connection reset by peer")}},
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "timeout is indeterminate",
			client:              &http.Client{Transport: errorTransport{err: context.DeadlineExceeded}},
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "server error is indeterminate",
			client:              common.ConstantResponseHttpClient(http.StatusInternalServerError, "{}"),
			wantVerified:        false,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := Scanner{client: test.client}.FromData(context.Background(), true, data)
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			got := results[0]
			if got.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", got.Verified, test.wantVerified)
			}
			if (got.VerificationError() != nil) != test.wantVerificationErr {
				t.Errorf("VerificationError() = %v, want error presence %v",
					got.VerificationError(), test.wantVerificationErr)
			}
			if e := got.VerificationError(); e != nil && strings.Contains(e.Error(), validSecret) {
				t.Errorf("verification error leaks the credential: %v", e)
			}
		})
	}
}
