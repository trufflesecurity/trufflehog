package kontent

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestKontent_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - with keyword kontent",
			input: `
				// the following are credentials for kontent.ai APIs - do not share with anyone
				kontent_personal_api_key = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJjOTE4OThlMWZlMGI0NDcwOTczOGM0ZmE0YzVlYzk0MyIsImlhdCI6MTc0NjUyNzQyNSwibmJmIjoxNzQ2NTI3NDI1LCJleHAiOjE3NjI0MjQ5NDAsInZlciI6IjMuMC4wIiwidWlkIjoidmlydHVhbF8zNTI4OGIxNC00YmE3LTQ5MzgtODZiNC1lYjFhYjczMDBiZTciLCJzY29wZV9pZCI6IjAyYmYxZDg5NzYzMjQ3ZWE4MTFkYjkwMjVhYjc0MTRhIiwicHJvamVjdF9jb250YWluZXJfaWQiOiI0MDFkMzg1NmMyYzUwMGZlOTYwMTE5YzFhMThkNWY4OCIsImF1ZCI6Im1hbmFnZS5rZW50aWNvY2xvdWQuY29tIn0.yfZTic9Zba6Dui8N6UO6t-SGbZYf17bKAd-uJ9enYPw
				kontent_env_id = 3d5f4d88-0511-00b3-37f1-31bb55c25ab4`,
			want: []string{"3d5f4d88-0511-00b3-37f1-31bb55c25ab4eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJjOTE4OThlMWZlMGI0NDcwOTczOGM0ZmE0YzVlYzk0MyIsImlhdCI6MTc0NjUyNzQyNSwibmJmIjoxNzQ2NTI3NDI1LCJleHAiOjE3NjI0MjQ5NDAsInZlciI6IjMuMC4wIiwidWlkIjoidmlydHVhbF8zNTI4OGIxNC00YmE3LTQ5MzgtODZiNC1lYjFhYjczMDBiZTciLCJzY29wZV9pZCI6IjAyYmYxZDg5NzYzMjQ3ZWE4MTFkYjkwMjVhYjc0MTRhIiwicHJvamVjdF9jb250YWluZXJfaWQiOiI0MDFkMzg1NmMyYzUwMGZlOTYwMTE5YzFhMThkNWY4OCIsImF1ZCI6Im1hbmFnZS5rZW50aWNvY2xvdWQuY29tIn0.yfZTic9Zba6Dui8N6UO6t-SGbZYf17bKAd-uJ9enYPw"},
		},
		{
			name: "invalid pattern",
			input: `
				// the following are credentials for kontent.ai APIs - do not share with anyone
				kontent_personal_api_key = eyJhbGciOiJIUzI1NiIsInR5cCVCJ9.eyJqdGkiOiJjOTE4OThlMWZlMGI0NDcwOTczOGM0ZmE0YzVlYzk0MyIsImlhdCI6MTc0NjUyNzQyNSwibmJmIjoxNzQ2NTI3NDI1LCJleHAiOjE3NjI0MjQ5NDAsInZlciI6IjMuMC4wIiwidWlkIjoidmlydHVhbF8zNTI4OGIxNC00YmE3LTQ5MzgtODZiNC1lYjFhYjczMDBiZTciLCJzY29wZV9pZCI6IjAyYmYxZDg5NzYzMjQ3ZWE4MTFkYjkwMjVhYjc0MTRhIiwicHJvamVjdF9jb250YWluZXJfaWQiOiI0MDFkMzg1NmMyYzUwMGZlOTYwMTE5YzFhMThkNWY4OCIsImF1ZCI6Im1hbmFnZS5rZW50aWNvY2xvdWQuY29tIn0.yfZTic9Zba6Dui8N6UO6t-SGbZYf17bKAd-uJ9enYPw
				kontent_env_id = 3d5f4d88-051-00b3-37f1-31bb55c25ab4`,
			want: []string{},
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
