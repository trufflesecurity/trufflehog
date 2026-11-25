package mailkube

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// The shared test vector of mailkube's own suites; it authenticates nowhere.
	validPattern = "mk_abcdefghijklmnopqrstuvwx_aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3d_1cbfd486fec407a9c8e6a37d8f22e0f12"
	// A key issued before the issuance tag: the API already refuses it.
	untaggedPattern = "mk_abcdefghijklmnopqrstuvwx_aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3d"
	// An uppercase key id is not a key mailkube issues.
	uppercasePattern = "mk_ABCDEFGHIJKLMNOPQRSTUVWX_aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3d_1cbfd486fec407a9c8e6a37d8f22e0f12"
)

func TestMailkube_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - environment variable",
			input: fmt.Sprintf("MAILKUBE_API_KEY=%s", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - bearer header",
			input: fmt.Sprintf("curl -H 'Authorization: Bearer %s' https://api.mailkube.com/mta/v1/emails", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("key = '%s' | '%s'", validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern - documentation placeholder",
			input: `MAILKUBE_API_KEY="mk_..."`,
			want:  []string{},
		},
		{
			name:  "invalid pattern - no issuance tag",
			input: fmt.Sprintf("MAILKUBE_API_KEY=%s", untaggedPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern - uppercase key id",
			input: fmt.Sprintf("MAILKUBE_API_KEY=%s", uppercasePattern),
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
