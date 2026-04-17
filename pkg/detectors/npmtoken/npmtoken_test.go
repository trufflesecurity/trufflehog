package npmtoken

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "3aAcac6c-9847-23d9-ce65-917590b81cf0"
	invalidPattern = "3aAcac6c?9847-23d9-ce65-917590b81cf0"
	keyword        = "npmtoken"
)

func TestNpmToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword npmtoken",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validPattern),
			want:  []string{},
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

func TestExtractTokenRegistryPairs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "single registry from npmrc",
			input: "//artifactory.example.com/:_authToken=3aAcac6c-9847-23d9-ce65-917590b81cf0",
			want:  map[string]string{"3aAcac6c-9847-23d9-ce65-917590b81cf0": "artifactory.example.com"},
		},
		{
			name:  "registry with path",
			input: "//nexus.example.com/repository/npm-proxy/:_authToken=3aAcac6c-9847-23d9-ce65-917590b81cf0",
			want:  map[string]string{"3aAcac6c-9847-23d9-ce65-917590b81cf0": "nexus.example.com/repository/npm-proxy"},
		},
		{
			name: "multiple registries with different tokens",
			input: `//artifactory.example.com/:_authToken=token1
//nexus.example.com/:_authToken=token2`,
			want: map[string]string{"token1": "artifactory.example.com", "token2": "nexus.example.com"},
		},
		{
			name:  "no registry",
			input: "npm token = 3aAcac6c-9847-23d9-ce65-917590b81cf0",
			want:  map[string]string{},
		},
		{
			name:  "duplicate token uses first registry",
			input: "//registry1.example.com/:_authToken=token1\n//registry2.example.com/:_authToken=token1",
			want:  map[string]string{"token1": "registry1.example.com"},
		},
		{
			name:  "registry with port number",
			input: "//localhost:4873/:_authToken=3aAcac6c-9847-23d9-ce65-917590b81cf0",
			want:  map[string]string{"3aAcac6c-9847-23d9-ce65-917590b81cf0": "localhost:4873"},
		},
		{
			name:  "registry with port and path",
			input: "//nexus.example.com:8081/repository/npm/:_authToken=3aAcac6c-9847-23d9-ce65-917590b81cf0",
			want:  map[string]string{"3aAcac6c-9847-23d9-ce65-917590b81cf0": "nexus.example.com:8081/repository/npm"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := extractTokenRegistryPairs(test.input)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("extractTokenRegistryPairs() diff: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestBuildRegistryURL(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		want     string
	}{
		{
			name:     "simple registry",
			registry: "registry.npmjs.org",
			want:     "https://registry.npmjs.org/-/whoami",
		},
		{
			name:     "registry with path",
			registry: "nexus.example.com/repository/npm-proxy",
			want:     "https://nexus.example.com/repository/npm-proxy/-/whoami",
		},
		{
			name:     "registry with https",
			registry: "https://artifactory.example.com",
			want:     "https://artifactory.example.com/-/whoami",
		},
		{
			name:     "registry with http",
			registry: "http://localhost:4873",
			want:     "http://localhost:4873/-/whoami",
		},
		{
			name:     "registry with trailing slash",
			registry: "registry.example.com/",
			want:     "https://registry.example.com/-/whoami",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := buildRegistryURL(test.registry)
			if got != test.want {
				t.Errorf("buildRegistryURL() = %v, want %v", got, test.want)
			}
		})
	}
}
