package smartsheets

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestSmartsheets_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - with keyword smartsheet and sheet",
			input: `
			# do not share these secrets
			# list all sheets
			sheets := getsmartsheet("MVE7zmdxouvunYkowLzaudyX7tvMpkqJ3q52C")
			`,
			want: []string{"MVE7zmdxouvunYkowLzaudyX7tvMpkqJ3q52C"},
		},
		{
			name: "valid pattern - with prefixRegex sheet",
			input: `
			# smartsheet credentials
			sheet_id := "MVE7zmdxouvunFAKELzaudyX7tvMpkqJ3q52d"
			`,
			want: []string{"MVE7zmdxouvunFAKELzaudyX7tvMpkqJ3q52d"},
		},
		{
			name: "valid pattern - ignore duplicate",
			input: `
			# smartsheet duplicate credentials
			sheet_id1 := "MVE7zmdxouvunFAKELzaudyX7tvMpkqJ3q52d"
			sheet_id2 := "MVE7zmdxouvunFAKELzaudyX7tvMpkqJ3q52d"
			`,
			want: []string{"MVE7zmdxouvunFAKELzaudyX7tvMpkqJ3q52d"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
			# below is the smartsheet secret
			# use this secret to list sheets
			# do not share this

			sslist := listAll("MVE7zmdxouvunFAKELzaudyX7tvMpkqJ3q52d")
			`,
			want: []string{},
		},
		{
			name: "valid pattern - 26 characters",
			input: `
			# smartsheet credentials
			sheet_token := "fakeiq999fakeecyfake3ifake"
			`,
			want: []string{"fakeiq999fakeecyfake3ifake"},
		},
		{
			name: "valid pattern - 26 and 37 characters",
			input: `
			# smartsheet multiple length credentials
			sheet_token := "fakeiq999fakeecyfake3ifake"
			sheet_token2 := "fakezmdxfakenFAKELzhonda7tvMpkqJ3fake"
			`,
			want: []string{"fakeiq999fakeecyfake3ifake", "fakezmdxfakenFAKELzhonda7tvMpkqJ3fake"},
		},
		{
			name: "invalid pattern - 30 characters",
			input: `
			# smartsheet invalid credentials
			sheet_token := "fakeiq999fakeecyfake3ifakeuiop"
			`,
			want: []string{},
		},
		{
			name: "invalid pattern",
			input: `
			# smartsheet secret
			sheet_id = MVE7?mdxouvunYkowLzaudyX7tvMpkqJ3q52C
			`,
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
