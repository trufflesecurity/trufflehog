package slack

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validBotToken                = "xoxb-65677559833-9613778673399u"
	invalidBotToken              = "xoxb-65677559833?9613778673399u"
	validUserToken               = "xoxp-24232636415-0285024315463c"
	invalidUserToken             = "xoxp-24232636415?0285024315463c"
	validWorkspaceAccessToken    = "xoxa-08532509747-07570405353c"
	invalidWorkspaceAccessToken  = "xoxa-08532509747?07570405353c"
	validWorkspaceRefreshToken   = "xoxr-833485595373-24619897332l"
	invalidWorkspaceRefreshToken = "xoxr-833485595373?24619897332l"
	keyword                      = "slack"
)

func TestSlack_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword slack",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, validBotToken, keyword, validUserToken, keyword, validWorkspaceAccessToken, keyword, validWorkspaceRefreshToken),
			want:  []string{validBotToken, validUserToken, validWorkspaceAccessToken, validWorkspaceRefreshToken},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, invalidBotToken, keyword, invalidUserToken, keyword, invalidWorkspaceAccessToken, keyword, invalidWorkspaceRefreshToken),
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
