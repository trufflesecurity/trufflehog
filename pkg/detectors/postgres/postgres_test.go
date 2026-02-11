package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validUriPattern           = "postgres://sN19x:d7N8bs@1.2.3.4:5432"
	invalidUriPattern         = "?ostgres://sN19x:d7N8bs@1.2.3.4:5432"
	validConnStrPartPattern   = "gVmMTdkwLwmZljcIOXhEmuZ='.jD#=-;|9tD!r^6('"
	invalidConnStrPartPattern = "gVmMTdkwLwmZljcIOXhEmu?='.jD#=-;|9tD!r^6('"
	keyword                   = "postgres"
)

func TestPostgres_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword postgres",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validUriPattern, keyword, validConnStrPartPattern),
			want:  []string{validUriPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidUriPattern, keyword, invalidConnStrPartPattern),
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

func TestPostgres_FromDataWithIgnorePattern(t *testing.T) {
	s := New(
		WithIgnorePattern([]string{
			`1\.2\.3\.4`,
		}))
	got, err := s.FromData(context.Background(), false, []byte(validUriPattern))
	if err != nil {
		t.Errorf("FromData() error = %v", err)
		return
	}
	if len(got) != 0 {
		t.Errorf("expected no results, but got %d", len(got))
	}
}
