package lob

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
	validPattern       = "live_0979969b3f6cc23ed67e9b650bfaf64f710"
	validPatternTest   = "test_0979969b3f6cc23ed67e9b650bfaf64f710"
	invalidPattern     = "live_0979969b3f6cc23ed67e9b650bfaf64f71"
	publishablePattern = "live_pub_0979969b3f6cc23ed67e9b650bfaf64"
)

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
		{
			name:  "snake_case identifier of key length",
			input: "def test_calculate_total_price_with_tax_rate():",
			want:  []string{},
		},
		{
			name:  "camelCase identifier of key length",
			input: "func test_someVeryLongCamelCaseFunctionNameXy() {}",
			want:  []string{},
		},
		{
			name:  "publishable key",
			input: fmt.Sprintf("token = '%s'", publishablePattern),
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

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestLob_Verify(t *testing.T) {
	lobError := func(code string) string {
		return fmt.Sprintf(`{"error":{"message":"...","status_code":403,"code":%q}}`, code)
	}

	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        bool
		wantErr     bool
	}{
		{
			name:   "active key",
			status: http.StatusUnprocessableEntity,
			body:   `{"error":{"message":"...","status_code":422,"code":"invalid"}}`,
			want:   true,
		},
		{
			name:   "invalid key",
			status: http.StatusUnauthorized,
			body:   `{"error":{"message":"...","status_code":401,"code":"invalid_api_key"}}`,
			want:   false,
		},
		{
			name:   "active key without a billing address",
			status: http.StatusForbidden,
			body:   lobError("billing_address_required"),
			want:   true,
		},
		{
			name:   "active key without a verified payment method",
			status: http.StatusForbidden,
			body:   lobError("payment_method_unverified"),
			want:   true,
		},
		{
			name:   "active key past its free request quota",
			status: http.StatusForbidden,
			body:   lobError("feature_limit_reached"),
			want:   true,
		},
		{
			name:   "invalid key reported as forbidden",
			status: http.StatusForbidden,
			body:   lobError("invalid_api_key"),
			want:   false,
		},
		{
			name:    "unrecognized error code",
			status:  http.StatusForbidden,
			body:    lobError("some_future_code"),
			wantErr: true,
		},
		{
			name:        "forbidden without an API response",
			status:      http.StatusForbidden,
			contentType: "text/html; charset=UTF-8",
			body:        "<!DOCTYPE html><html><head><title>Attention Required!</title></head></html>",
			wantErr:     true,
		},
		{
			name:    "unexpected status",
			status:  http.StatusInternalServerError,
			body:    `{"error":{"message":"...","status_code":500,"code":"internal_server_error"}}`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				username, _, ok := req.BasicAuth()
				if !ok || username != validPattern {
					t.Errorf("basic auth username = %q (ok=%t), want %q", username, ok, validPattern)
				}
				contentType := test.contentType
				if contentType == "" {
					contentType = "application/json; charset=utf-8"
				}
				return &http.Response{
					StatusCode: test.status,
					Header:     http.Header{"Content-Type": []string{contentType}},
					Body:       io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})}}

			got, err := s.verify(context.Background(), validPattern)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %t", err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("verified = %t, want %t", got, test.want)
			}
		})
	}
}
