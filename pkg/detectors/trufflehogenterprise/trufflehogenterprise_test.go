package trufflehogenterprise

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
    validKey        = "thog-key-946c7e0fbee2baff"
    invalidKey      = "thog-key-946?7e0fbee2baff"
    validSecret     = "thog-secret-8fbfc135085421e62d8f1982af17bbf6"
    invalidSecret   = "thog-secret-8fbfc13?085421e62d8f1982af17bbf6"
    validHostname   = "uryfanaextzftqnwkordjwtrascqbihyctwttsntssxgbmgtnghmaiossoiablwqntsnudfdz-grthynfwdntsfdyuvk-tqfecqndhkmebecezcyzptxnsgprzkdcwzwnzdxpm.v6.zfjkrzjmutvvwwqftipvtkdwg.trufflehog.org"
    invalidHostname = "?ryfanaextzftqnwkordjwtrascqbihyctwttsntssxgbmgtnghmaiossoiablwqntsnudfdz-grthynfwdntsfdyuvk-tqfecqndhkmebecezcyzptxnsgprzkdcwzwnzdxpm.v6.zfjkrzjmutvvwwqftipvtkdwg.trufflehog.org"
    keyword         = "trufflehogenterprise"
)

func TestTrufflehogenterprise_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword trufflehogenterprise",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, validKey, keyword, validSecret, keyword, validHostname),
			want:  []string{validKey},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, invalidKey, keyword, invalidSecret, keyword, invalidHostname),
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
