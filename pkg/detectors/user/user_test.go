package user

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKey   = "9UgOsRfud4RTyBQpJQFOQiwNQcfeLGHH1DDoxhgzCvBmccmVQ7MYB0ai3LXGZNMf"
	validURL   = "https://testdetector.user.com"
	invalidKey = "OmFxWjhZvCpOeMsgTJdZMas+dlUpr=fa?+.QOKKYvi7RKWyBeHtaLa7_rzMhLrRd"
	keyword    = "user.com"
)

func TestUser_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - key and url present",
			input: fmt.Sprintf("user token = '%s'\nurl = %s", validKey, validURL),
			want:  []string{validKey + ":" + validURL},
		},
		{
			name:  "valid pattern - ignore duplicate keys",
			input: fmt.Sprintf("user token = '%s' | '%s'\nurl = %s", validKey, validKey, validURL),
			want:  []string{validKey + ":" + validURL},
		},
		{
			name:  "no result - key without url",
			input: fmt.Sprintf("user token = '%s'", validKey),
			want:  []string{},
		},
		{
			name:  "no result - url without key",
			input: fmt.Sprintf("%s url = %s", keyword, validURL),
			want:  []string{},
		},
		{
			name:  "no result - key out of prefix range",
			input: fmt.Sprintf("user keyword is not close to the real key in the data\n = '%s'\nurl = %s", validKey, validURL),
			want:  []string{},
		},
		{
			name:  "no result - invalid key format",
			input: fmt.Sprintf("user = '%s'\nurl = %s", invalidKey, validURL),
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			s := Scanner{}
			s.UseFoundEndpoints(true)
			results, err := s.FromData(context.Background(), false, []byte(test.input))
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
