package metabase

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
	validKeyPattern       = "Y49ftoUer6aYZOzdkRzlENnW8PHnD9zf9dP9"
	invalidKeyPattern     = "=49ftoUer6aYZOzdkRzlENnW8PHnD9zf9dP9"
	validBaseUrlPattern   = "https://tiwRdoa.metabase.com"
	invalidBaseUrlPattern = "https://tiwRdo^.metabase.com"
	keyword               = "metabase"
)

func TestMetabase_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword metabase",
			input: fmt.Sprintf("%s '%s' %s '%s'", keyword, validKeyPattern, keyword, validBaseUrlPattern),
			want:  []string{validKeyPattern + validBaseUrlPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s' '%s'", keyword, validKeyPattern, validBaseUrlPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = '%s' url = '%s'", keyword, invalidKeyPattern, invalidBaseUrlPattern),
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestMetabase_IsMetabaseMarketingHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "metabase.com", want: true},
		{host: "www.metabase.com", want: true},
		{host: "WWW.METABASE.COM", want: true},
		{host: "metabase.com.", want: true},
		{host: "mycompany.metabase.com", want: false},
		{host: "tiwRdoa.metabase.com", want: false},
		{host: "metabase.example.com", want: false},
		{host: "notmetabase.com", want: false},
		{host: "metabase.com.evil.com", want: false},
		{host: "example.com", want: false},
	}

	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			if got := isMetabaseMarketingHost(test.host); got != test.want {
				t.Errorf("isMetabaseMarketingHost(%q) = %v, want %v", test.host, got, test.want)
			}
		})
	}
}

// TestMetabase_MarketingHostSkipped is the regression test for
// trufflesecurity/trufflehog#5584: a docs link on www.metabase.com next to a
// UUID session token was verified against the marketing site, producing 404
// noise. Marketing hosts must be skipped without any verification request,
// while a subdomain instance URL next to the same docs link must still be
// verified.
func TestMetabase_MarketingHostSkipped(t *testing.T) {
	validUUID := "123e4567-e89b-12d3-a456-426614174000"

	tests := []struct {
		name             string
		input            string
		wantResults      int
		wantVerified     bool
		wantRequestHosts []string
	}{
		{
			// The reporter's exact repro: METABASE_URL points at the docs
			// site and the token is a UUID session token.
			name:             "www.metabase.com docs link is skipped",
			input:            fmt.Sprintf("%s METABASE_URL=https://www.metabase.com/docs/latest/api %s session = '%s'", keyword, keyword, validUUID),
			wantResults:      0,
			wantVerified:     false,
			wantRequestHosts: nil,
		},
		{
			name:             "bare metabase.com is skipped",
			input:            fmt.Sprintf("%s METABASE_URL=https://metabase.com %s session = '%s'", keyword, keyword, validUUID),
			wantResults:      0,
			wantVerified:     false,
			wantRequestHosts: nil,
		},
		{
			name:             "subdomain instance is still verified",
			input:            fmt.Sprintf("%s session = '%s' %s url = 'https://mycompany.metabase.com'", keyword, validUUID, keyword),
			wantResults:      1,
			wantVerified:     true,
			wantRequestHosts: []string{"mycompany.metabase.com"},
		},
		{
			name:             "real instance next to docs link is still verified",
			input:            fmt.Sprintf("%s METABASE_URL=https://www.metabase.com/docs/latest/api %s session = '%s' %s url = 'https://mycompany.metabase.com'", keyword, keyword, validUUID, keyword),
			wantResults:      1,
			wantVerified:     true,
			wantRequestHosts: []string{"mycompany.metabase.com"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prevClient := client
			t.Cleanup(func() {
				client = prevClient
			})

			var requestHosts []string
			client = &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					requestHosts = append(requestHosts, req.URL.Host)
					if req.URL.Path != "/api/user/current" {
						t.Errorf("unexpected verification path: %s", req.URL.Path)
					}
					if req.Header.Get("X-Metabase-Session") != validUUID {
						t.Errorf("unexpected X-Metabase-Session header: %q", req.Header.Get("X-Metabase-Session"))
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"id":1}`)),
						Header:     make(http.Header),
					}, nil
				}),
			}

			d := Scanner{}
			results, err := d.FromData(context.Background(), true, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData returned error: %v", err)
			}
			if diff := cmp.Diff(test.wantRequestHosts, requestHosts); diff != "" {
				t.Errorf("verification request hosts diff: (-want +got)\n%s", diff)
			}
			if len(results) != test.wantResults {
				t.Fatalf("expected %d results, got %d: %+v", test.wantResults, len(results), results)
			}
			for _, r := range results {
				if r.Verified != test.wantVerified {
					t.Errorf("Verified = %v, want %v", r.Verified, test.wantVerified)
				}
			}
		})
	}
}
