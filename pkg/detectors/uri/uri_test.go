package uri

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "https://kaNydBSAodo87dsm9asuiSAFtsd7.com:1234@qYY3SylY7fHP"
	validPattern2  = `<p><a href="http://username:password@127.0.0.1">http://username:password@127.0.0.1</a></p>`
	invalidPattern = "https://kaNydBSAodo87dsm9asuiSAFtsd7.com.1234@qYY3SylY7fHP"
	keyword        = "uri"
)

func TestURI_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword uri",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - do not process duplicate",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern2),
			want:  []string{"http://username:password@127.0.0.1"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
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

func TestURI_ReservedHostnames(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     int
	}{
		{name: "local", hostname: "service.local", want: 0},
		{name: "localhost", hostname: "service.localhost", want: 0},
		{name: "test", hostname: "service.test", want: 0},
		{name: "invalid", hostname: "service.invalid", want: 0},
		{name: "example", hostname: "service.example", want: 0},
		{name: "example com", hostname: "proxy.example.com", want: 0},
		{name: "example net", hostname: "proxy.example.net", want: 0},
		{name: "example org", hostname: "proxy.example.org", want: 0},
		{name: "case insensitive", hostname: "Service.LOCAL", want: 0},
		{name: "trailing dot", hostname: "service.local.", want: 0},
		{name: "non reserved", hostname: "service.locality.example.dev", want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := fmt.Sprintf("http://username:password@%s/path", test.hostname)
			results, err := (Scanner{}).FromData(context.Background(), false, []byte(input))
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if len(results) != test.want {
				t.Fatalf("FromData() returned %d results, want %d", len(results), test.want)
			}
		})
	}
}
