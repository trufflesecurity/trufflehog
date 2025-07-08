package snykkey

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"testing"
)

func TestSnyk_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "typical pattern",
			input: `set NODE_REQUIRED_VERSION=12.13.1
set SNYK_API_TOKEN=885953dc-2469-443c-983d-5243d2d54116

set PATH=%PATH%;C:\Program Files\nodejs\;C:\Program Files\Git\cmd`,
			want: []string{"885953dc-2469-443c-983d-5243d2d54116"},
		},
		// https://docs.snyk.io/snyk-api/get-a-projects-sbom-document-endpoint#how-to-generate-the-sbom-for-a-project
		//	{
		//		name: "curl example",
		//		`curl --get \
		// -H "Authorization: token ccc9ae71-913f-46bd-9d23-03356323400a" \
		// --data-urlencode "version=2023-03-20" \
		// --data-urlencode "format=cyclonedx1.4%2Bjson" \
		// https://api.snyk.io/rest/orgs/1234/projects/1234/sbom`,
		//	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matches) == 0 {
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
