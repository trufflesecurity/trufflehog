package shipmail

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validLive = "sm_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDA"
	validTest = "sm_test_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDA"
)

func TestShipmail_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "live key", input: fmt.Sprintf("SHIPMAIL_API_KEY=%s", validLive), want: []string{validLive}},
		{name: "test key", input: fmt.Sprintf("SHIPMAIL_API_KEY='%s'", validTest), want: []string{validTest}},
		{name: "duplicate", input: fmt.Sprintf("%s %s", validLive, validLive), want: []string{validLive}},
		{name: "too short", input: "SHIPMAIL_API_KEY=sm_live_short", want: []string{}},
		{name: "placeholder", input: "Authorization: Bearer sm_live_...", want: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf("keywords were not matched for input: %s", test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestShipmail_Verify(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		verified bool
		wantErr  bool
	}{
		{name: "live key", status: http.StatusOK, verified: true},
		{name: "live key limited to an IP allowlist", status: http.StatusForbidden, verified: true},
		{name: "revoked or unknown key", status: http.StatusUnauthorized, verified: false},
		{name: "rate limited", status: http.StatusTooManyRequests, verified: false, wantErr: true},
		{name: "server error", status: http.StatusServiceUnavailable, verified: false, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if got := r.Header.Get("Authorization"); got != "Bearer "+validLive {
					t.Errorf("Authorization = %q", got)
				}
				if r.Method != http.MethodGet || r.URL.String() != verifyURL {
					t.Errorf("request = %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}

			verified, err := verifyMatch(context.Background(), client, validLive)
			if verified != test.verified {
				t.Errorf("verified = %v, want %v", verified, test.verified)
			}
			if (err != nil) != test.wantErr {
				t.Errorf("err = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
