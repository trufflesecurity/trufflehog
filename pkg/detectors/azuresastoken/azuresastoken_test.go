package azuresastoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
	AZURE_BLOB_SAS_TOKEN=sp=r&st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c&sig=WSdF9YeZhvrbs%2B%2B1f8ZdDBzEe7fBJ%2BenuaXQ%2BJ9WOw0%3D
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/trufflesecurity
	`
	invalidPattern = `
	AZURE_BLOB_SAS_TOKEN=st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/12trufflesecurity
	`
)

func TestAzureSASToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{"https://trufflesecurity.blob.core.windows.net/trufflesecuritysp=r&st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c&sig=WSdF9YeZhvrbs%2B%2B1f8ZdDBzEe7fBJ%2BenuaXQ%2BJ9WOw0%3D"},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  nil,
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
