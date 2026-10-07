package netsuite

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validConsumerKey      = "3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15"
	invalidConsumerKey    = "3Wa?Ed0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15"
	validConsumerSecret   = "5BZ70LfNshsJkDya1XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD"
	invalidConsumerSecret = "5BZ70LfNshsJkDya?XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD"
	validTokenKey         = "KeYcG56ViFDleXPFJuEQ5CAGSJn7o2WDa5iGvLIvVBqZj5rMkaWFmzkp4bveJa74"
	invalidTokenKey       = "KeYcG56ViFDleXPFJuEQ5CAGSJn7o2WD?5iGvLIvVBqZj5rMkaWFmzkp4bveJa74"
	validTokenSecret      = "GGQUdyYOGDfDImJWCz4Kufk2GevaIDuVv83kIa9zCRuXIDLB4oh2eVDVPmsaSai2"
	invalidTokenSecret    = "GGQUdyYOGDfDImJWCz4Kufk2Ge?aIDuVv83kIa9zCRuXIDLB4oh2eVDVPmsaSai2"
	validAccountID        = "x1L2_BXo"
	invalidAccountID      = "x1L2?BXo"
	keyword               = "netsuite"
	inputFormat           = `%s id - '%s'
consumer - '%s' consumer - '%s'
token - '%s' token - '%s'`
	outputPair1 = validConsumerKey + validConsumerSecret
	outputPair2 = validConsumerSecret + validConsumerKey
)

func TestNetsuite_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword netsuite",
			input: fmt.Sprintf(inputFormat, keyword, validAccountID, validConsumerKey, validConsumerSecret, validTokenKey, validTokenSecret),
			want:  []string{outputPair1, outputPair2},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf(inputFormat, keyword, invalidAccountID, invalidConsumerKey, invalidConsumerSecret, invalidTokenKey, invalidTokenSecret),
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

// denseValue returns the i-th 64-character value of tokenDenseInput.
func denseValue(i int) string {
	return fmt.Sprintf("%064x", i)
}

// tokenDenseInput returns n distinct 64-character values, each of which every key and secret pattern matches, and one
// account ID.
func tokenDenseInput(n int) []byte {
	var input strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&input, "netsuite = %s\n", denseValue(i))
	}
	input.WriteString("account_id = 1234567\n")
	return []byte(input.String())
}

// fakeClient returns a client that counts its requests and answers each with the status respond picks.
func fakeClient(requests *atomic.Int32, respond func(req *http.Request) int) *http.Client {
	return &http.Client{
		Transport: common.FakeTransport{
			CreateResponse: func(req *http.Request) (*http.Response, error) {
				requests.Add(1)
				return &http.Response{
					Request:    req,
					StatusCode: respond(req),
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			},
		},
	}
}

func TestNetsuite_TokenDenseInput(t *testing.T) {
	const values = 16

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := Scanner{}.FromData(ctx, false, tokenDenseInput(values))
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	// One result per ordered consumer key and secret pair, not one per combination of all five parts.
	if want := values * (values - 1); len(results) != want {
		t.Fatalf("expected %d results, got %d", want, len(results))
	}
	seen := make(map[string]struct{}, len(results))
	for _, r := range results {
		if _, ok := seen[string(r.RawV2)]; ok {
			t.Fatalf("duplicate result %q", r.RawV2)
		}
		seen[string(r.RawV2)] = struct{}{}
	}
}

func TestNetsuite_Verification(t *testing.T) {
	// With 4 values there are 4*3 consumer key and secret pairs, each completed by 2*1 token key and secret orders.
	tests := []struct {
		name         string
		values       int
		status       int
		cancel       bool
		wantVerified bool
		wantErr      string
		wantRequests int32
	}{
		{
			name:         "rejected pairs try every combination",
			values:       4,
			status:       http.StatusUnauthorized,
			wantRequests: 12 * 2,
		},
		{
			name:         "verification stops at the first accepted combination",
			values:       4,
			status:       http.StatusOK,
			wantVerified: true,
			wantRequests: 12,
		},
		{
			name:         "canceled context sends no requests",
			values:       16,
			status:       http.StatusOK,
			cancel:       true,
			wantErr:      context.Canceled.Error(),
			wantRequests: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			client := fakeClient(&requests, func(*http.Request) int { return tt.status })

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}

			results, err := Scanner{client: client}.FromData(ctx, true, tokenDenseInput(tt.values))
			if err != nil {
				t.Fatalf("error = %v", err)
			}

			if want := tt.values * (tt.values - 1); len(results) != want {
				t.Fatalf("expected %d results, got %d", want, len(results))
			}
			for _, r := range results {
				if r.Verified != tt.wantVerified {
					t.Fatalf("verified = %v, want %v", r.Verified, tt.wantVerified)
				}
				var gotErr string
				if err := r.VerificationError(); err != nil {
					gotErr = err.Error()
				}
				if gotErr != tt.wantErr {
					t.Fatalf("verification error = %q, want %q", gotErr, tt.wantErr)
				}
			}
			if got := requests.Load(); got != tt.wantRequests {
				t.Errorf("requests = %d, want %d", got, tt.wantRequests)
			}
		})
	}
}

func TestNetsuite_VerificationFindsTheAcceptedCombination(t *testing.T) {
	// Accept only consumer key 1 with token key 4, so each pair has at most one accepted combination among the
	// rejected ones.
	var requests atomic.Int32
	client := fakeClient(&requests, func(req *http.Request) int {
		auth := req.Header.Get("Authorization")
		if strings.Contains(auth, `oauth_consumer_key="`+denseValue(1)+`"`) &&
			strings.Contains(auth, `oauth_token="`+denseValue(4)+`"`) {
			return http.StatusOK
		}
		return http.StatusUnauthorized
	})

	results, err := Scanner{client: client}.FromData(context.Background(), true, tokenDenseInput(4))
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	// Token key 4 completes consumer key 1 with secret 2 or 3, but not with secret 4.
	want := map[string]struct{}{
		denseValue(1) + denseValue(2): {},
		denseValue(1) + denseValue(3): {},
	}
	got := make(map[string]struct{})
	for _, r := range results {
		if r.Verified {
			got[string(r.RawV2)] = struct{}{}
		}
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("verified pairs diff: (-want +got)\n%s", diff)
	}
}

func TestNetsuite_VerificationMissingHost(t *testing.T) {
	invalidHosts.Clear()
	t.Cleanup(invalidHosts.Clear)

	var requests atomic.Int32
	client := &http.Client{
		Transport: common.FakeTransport{
			CreateResponse: func(req *http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, &net.DNSError{Err: "no such host", Name: req.URL.Hostname(), IsNotFound: true}
			},
		},
	}
	s := Scanner{client: client}

	// Scan twice, as if the data were split across two chunks. A missing host is unverified, as before.
	for range 2 {
		results, err := s.FromData(context.Background(), true, tokenDenseInput(4))
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if len(results) != 12 {
			t.Fatalf("expected 12 results, got %d", len(results))
		}
		for _, r := range results {
			if r.Verified || r.VerificationError() != nil {
				t.Fatalf("verified = %v, verification error = %v, want unverified", r.Verified, r.VerificationError())
			}
		}
	}

	// The first lookup caches the host, so no later combination or chunk looks it up again.
	if got := requests.Load(); got != 1 {
		t.Errorf("requests = %d, want 1", got)
	}
}
