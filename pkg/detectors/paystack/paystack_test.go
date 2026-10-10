package paystack

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestPaystack_Pattern(t *testing.T) {
	d := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	upper := strings.Repeat("A", 40)
	mixed := "AbCdEfGhIjKlMnOpQrStUvWx1234567890ABCDEF"
	lower := strings.Repeat("b", 40)
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "test key lowercase payload", input: "sk_test_" + lower, want: []string{"sk_test_" + lower}},
		{name: "live key uppercase payload", input: "sk_live_" + upper, want: []string{"sk_live_" + upper}},
		{name: "test key mixed-case payload", input: "sk_test_" + mixed, want: []string{"sk_test_" + mixed}},
		{name: "public key is not a secret", input: "pk_test_" + upper},
		{name: "reject 39-character payload", input: "sk_test_" + upper[:39]},
		{name: "reject 41-character payload", input: "sk_live_" + upper + "A"},
		{name: "reject punctuation", input: "sk_test_" + upper[:20] + "?" + upper[21:]},
		{name: "reject unsupported environment label", input: "sk_prod_" + upper},
		{name: "reject uppercase environment label", input: "sk_TEST_" + upper},
		{name: "reject embedded prefix", input: "xsk_test_" + upper},
		{name: "reject trailing word character", input: "sk_test_" + upper + "x"},
		{name: "reject whitespace in payload", input: "sk_test_" + upper[:20] + " " + upper[20:]},
		{name: "not found", input: "ordinary configuration without credentials"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.want) > 0 && len(core.FindDetectorMatches([]byte(tc.input))) == 0 {
				t.Fatalf("keywords %v did not match input", d.Keywords())
			}
			results, err := d.FromData(context.Background(), false, []byte(tc.input))
			if err != nil {
				t.Fatalf("FromData error: %v", err)
			}
			got := make(map[string]struct{}, len(results))
			for _, result := range results {
				got[string(result.Raw)] = struct{}{}
				if result.SecretParts["key"] != string(result.Raw) {
					t.Errorf("SecretParts[key] = %q, want %q", result.SecretParts["key"], result.Raw)
				}
			}
			want := make(map[string]struct{}, len(tc.want))
			for _, value := range tc.want {
				want[value] = struct{}{}
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

type paystackTestRoundTripper func(*http.Request) (*http.Response, error)

func (f paystackTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPaystackVerificationUsesInjectedClient(t *testing.T) {
	key := "sk_test_" + strings.Repeat("A", 40)
	client := &http.Client{Transport: paystackTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != verifyURL {
			t.Errorf("URL = %q, want %q", req.URL, verifyURL)
		}
		if req.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", req.Method)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer "+key {
			t.Errorf("Authorization = %q", got)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header), Request: req}, nil
	})}
	d := Scanner{client: client}
	results, err := d.FromData(context.Background(), true, []byte(key))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}
	if len(results) != 1 || !results[0].Verified {
		t.Fatalf("results = %#v, want one verified result", results)
	}
}
