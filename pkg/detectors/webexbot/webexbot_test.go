package webexbot

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestWebexbot_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "webexbot_token = 'ajlksdjasda9090sadsa9dsad0saasdkl0asd90asdcasc90asdajij2n2njkjn3_asdf_asdkqw34-qwer-vbnm-asdf-qwertyuiopkl'",
			want:  []string{"ajlksdjasda9090sadsa9dsad0saasdkl0asd90asdcasc90asdajij2n2njkjn3_asdf_asdkqw34-qwer-vbnm-asdf-qwertyuiopkl"},
		},
		{
			name: "finds multiple Webex Bot tokens",
			input: `
			webex_bot_token = 'ajlksdjasda9090sadsa9dsad0saasdkl0asd90asdcasc90asdajij2n2njkjn3_qwer_zxcv1234-asdf-ghjk-tyui-mnbvcxzqwert'
			webexbot = "ajlksdjasda9090sadsa9dsad0saasdkl0asd90asdcasc90asdajij2n2njkjn3_asdf_qwer4567-qwer-vbnm-asdf-xcvbnmasdfgh"
		`,
			want: []string{
				"ajlksdjasda9090sadsa9dsad0saasdkl0asd90asdcasc90asdajij2n2njkjn3_qwer_zxcv1234-asdf-ghjk-tyui-mnbvcxzqwert",
				"ajlksdjasda9090sadsa9dsad0saasdkl0asd90asdcasc90asdajij2n2njkjn3_asdf_qwer4567-qwer-vbnm-asdf-xcvbnmasdfgh",
			},
		},
		{
			name:  "does not match invalid token name",
			input: "webex = 'asdf1234qwer5678zxcv9012lkjh_asdf_qwer3456-qwer-vbnm-asdf-zxcvbnmasdfgh'",
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
