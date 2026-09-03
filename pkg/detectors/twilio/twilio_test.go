package twilio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-retryablehttp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validSid   = "AC1b3f0bddbb6887d68d8454e66c749c6a"
	invalidSid = "AC1b3f0bddbb?887d68d8454e66c749c6a"
	validKey   = "daf7b3d34b9787f1212316eea62ba186"
	invalidKey = "daf7b3d34b9787f1?12316eea62ba186"
	keyword    = "twilio"
)

func TestTwilio_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword twilio",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validSid, keyword, validKey),
			want:  []string{validSid + validKey},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidSid, keyword, invalidKey),
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
type errorTransport struct{ err error }

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

func TestTwilio_VerificationDeterminacy(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio sid %s key %s", validSid, validKey))

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
			name:                "rate limit reaching the switch is indeterminate",
			client:              common.ConstantResponseHttpClient(http.StatusTooManyRequests, ""),
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
			if e := got.VerificationError(); e != nil && strings.Contains(e.Error(), validKey) {
				t.Errorf("verification error leaks the credential: %v", e)
			}
		})
	}
}

func TestTwilio_RetryExhaustionIsIndeterminate(t *testing.T) {
	var attempts int32

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil
	retryClient.RetryWaitMin = time.Millisecond
	retryClient.RetryWaitMax = 2 * time.Millisecond
	retryClient.HTTPClient.Transport = common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&attempts, 1)
			return &http.Response{
				Request:    req,
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	}

	data := []byte(fmt.Sprintf("twilio sid %s key %s", validSid, validKey))
	results, err := Scanner{client: retryClient.StandardClient()}.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if got := atomic.LoadInt32(&attempts); got != 4 {
		t.Errorf("expected 4 attempts (initial + RetryMax), got %d", got)
	}
	if results[0].Verified {
		t.Error("Verified = true, want false")
	}
	if results[0].VerificationError() == nil {
		t.Error("VerificationError() = nil; a throttled credential would be recorded as rotated")
	}
}
