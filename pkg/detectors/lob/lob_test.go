package lob

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern     = "live_0979969b3f6cc23ed67e9b650bfaf64f710"
	validPatternTest = "test_0979969b3f6cc23ed67e9b650bfaf64f710"
	invalidPattern   = "live_0979969b3f6cc23ed67e9b650bfaf64f71"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestLob_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid live pattern",
			input: fmt.Sprintf("token = '%s'", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid test pattern",
			input: fmt.Sprintf("token = '%s'", validPatternTest),
			want:  []string{validPatternTest},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("token = '%s' | '%s'", validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("'%s'", invalidPattern),
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

func TestLob_VerifyStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{
			name:       "forbidden is unverified",
			statusCode: http.StatusForbidden,
			want:       false,
		},
		{
			name:       "unauthorized is unverified",
			statusCode: http.StatusUnauthorized,
			want:       false,
		},
		{
			name:       "unprocessable entity is verified",
			statusCode: http.StatusUnprocessableEntity,
			want:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := Scanner{
				client: &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if req.Method != http.MethodPost {
							t.Errorf("method = %q, want %q", req.Method, http.MethodPost)
						}
						if req.URL.String() != "https://api.lob.com/v1/us_verifications" {
							t.Errorf("url = %q, want https://api.lob.com/v1/us_verifications", req.URL.String())
						}
						username, password, ok := req.BasicAuth()
						if !ok {
							t.Fatal("expected basic auth")
						}
						if username != validPattern {
							t.Errorf("username = %q, want %q", username, validPattern)
						}
						if password != "" {
							t.Errorf("password = %q, want empty", password)
						}
						return &http.Response{
							StatusCode: test.statusCode,
							Body:       http.NoBody,
						}, nil
					}),
				},
			}

			got, err := scanner.verify(context.Background(), validPattern)
			if err != nil {
				t.Fatalf("verify returned error: %v", err)
			}
			if got != test.want {
				t.Errorf("verify = %t, want %t", got, test.want)
			}
		})
	}
}
