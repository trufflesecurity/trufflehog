package flutterwave

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

func TestFlutterWave_Pattern(t *testing.T) {
	d := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	lower := "abcdefghijklmnopqrstuvwx12345678"
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
	mixed := "AbCdEfGhIjKlMnOpQrStUvWx12345678"
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "live lowercase key", input: "FLWSECK-" + lower + "-X", want: []string{"FLWSECK-" + lower + "-X"}},
		{name: "test uppercase key", input: "FLWSECK_TEST-" + upper + "-X", want: []string{"FLWSECK_TEST-" + upper + "-X"}},
		{name: "test mixed-case key in config", input: `{"flutterwave_secret":"FLWSECK_TEST-` + mixed + `-X"}`, want: []string{"FLWSECK_TEST-" + mixed + "-X"}},
		{name: "public key is not a secret", input: "FLWPUBK_TEST-" + upper + "-X"},
		{name: "reject 31-character payload", input: "FLWSECK-" + lower[:31] + "-X"},
		{name: "reject 33-character payload", input: "FLWSECK-" + lower + "9-X"},
		{name: "reject invalid punctuation", input: "FLWSECK_TEST-" + lower[:16] + "?" + lower[17:] + "-X"},
		{name: "reject wrong suffix", input: "FLWSECK_TEST-" + lower + "-XX"},
		{name: "reject unsupported environment label", input: "FLWSECK_PROD-" + lower + "-X"},
		{name: "reject embedded prefix", input: "xFLWSECK-" + lower + "-X"},
		{name: "reject extra trailing word character", input: "FLWSECK-" + lower + "-X9"},
		{name: "reject whitespace in payload", input: "FLWSECK-" + lower[:16] + " " + lower[16:] + "-X"},
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

type flutterwaveTestRoundTripper func(*http.Request) (*http.Response, error)

func (f flutterwaveTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFlutterwaveVerificationUsesInjectedClient(t *testing.T) {
	client := &http.Client{Transport: flutterwaveTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != verifyURL {
			t.Errorf("URL = %q, want %q", req.URL, verifyURL)
		}
		if req.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", req.Method)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer FLWSECK_TEST-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456-X" {
			t.Errorf("Authorization = %q", got)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header), Request: req}, nil
	})}
	d := Scanner{client: client}
	results, err := d.FromData(context.Background(), true, []byte("FLWSECK_TEST-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456-X"))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}
	if len(results) != 1 || !results[0].Verified {
		t.Fatalf("results = %#v, want one verified result", results)
	}
}
