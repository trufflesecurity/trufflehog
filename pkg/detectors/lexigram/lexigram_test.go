package lexigram

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "FyIcB4LRVZ4iEJVky0JvzVS6yzreDuFgz8zSmfXNlWuEIE29ad6Wmc9sQtUzWBp8dV960IeSdWk5V182naPy0uAty27gdFtyl6TvCz0gJdprxKyZfNzxVeAy5Qlghzl4Ivk9jXe2p7gnafM3iUvK2vemq5FroXXgUJTZ0SHqR6QGv0wk9WGEa5aAxDUiQ91e2xI6leUbTIoxXQyF1P1rxYZswimIbGTHy6H7oMuTbXFrX3XDdphMqyHYjGlzYDfY3nREvC83XsgIlawdTV0FdPXzXxqB4ELorpo3z8kCsWm1H"
	invalidPattern = "=yIcB4LRVZ4iEJVky0JvzVS6yzreDuFgz8zSmfXNlWuEIE29ad6Wmc9sQtUzWBp8dV960IeSdWk5V182naPy0uAty27gdFtyl6TvCz0gJdprxKyZfNzxVeAy5Qlghzl4Ivk9jXe2p7gnafM3iUvK2vemq5FroXXgUJTZ0SHqR6QGv0wk9WGEa5aAxDUiQ91e2xI6leUbTIoxXQyF1P1rxYZswimIbGTHy6H7oMuTbXFrX3XDdphMqyHYjGlzYDfY3nREvC83XsgIlawdTV0FdPXzXxqB4ELorpo3z8kCsWm1H"
	keyword        = "lexigram"
)

func TestLexigram_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword lexigram",
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
