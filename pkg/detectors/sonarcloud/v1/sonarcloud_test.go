package sonarcloud

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye"
	invalidPattern = "hxrxxgxt?jxj7ta3dn33c5r5i2h0i6cqjv9kwkye"
	keyword        = "sonarcloud"
)

func TestSonarCloud_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword sonarcloud",
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
		{
			name:  "invalid pattern - token directly preceded by @",
			input: fmt.Sprintf("%s token = '@%s'", keyword, validPattern),
			want:  []string{},
		},
		{
			// Regression test for issue #5000: dependabot PR bodies contain
			// "github.com/<org>/<repo>/commit/<40-char-sha>" URLs whose SHA-1
			// hashes otherwise look exactly like a SonarCloud token and are
			// preceded by the "sonar" keyword within the prefix window.
			name:  "github commit sha is not a sonar token",
			input: fmt.Sprintf("Updates sonarsource/sonarqube-scan-action. See https://github.com/SonarSource/sonarqube-scan-action/commit/56568530eddcb15ab65e7880af318fba5b859e2e for details."),
			want:  []string{},
		},
		{
			// Same family of FP: a bare "commit/<sha>" path with the keyword
			// elsewhere in the window must also be rejected.
			name:  "commit path without host is not a sonar token",
			input: fmt.Sprintf("sonar scanner bumped, see commit/7006c4492b2e0ee0f816d36501671557c97f5995 in the upstream repo"),
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
