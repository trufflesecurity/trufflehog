package sumologickey

import (
	"context"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"

	"github.com/google/go-cmp/cmp"
)

func TestSumoLogicKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "typical pattern",
			input: `sumologic:
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL
  clusterName: Kubernetes_cluster-2024-10-25T21:34:23.096Z`,
			want: []string{`{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL"}`},
		},
		{
			name: "pattern with url",
			input: `sumologic:
  baseUrl: api.us2.sumologic.com
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL
  clusterName: Kubernetes_cluster-2024-10-25T21:34:23.096Z`,
			want: []string{`{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL","url":"api.us2.sumologic.com"}`},
		},
		{
			name: "finds all matches",
			input: `sumoId1 = 'suaRYt6iLL8cxl'
sumoKey1 = 'CzrMhR8zzy1eH1F0XlY1tu5ywqa2yaSFoWGg2cqE43XkfnUVCytnPQfv1enUYrzv'
sumoId2 = 'suDkVYKjXZBwsz'
sumoKey2 = 'Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK21a0LckgRSCL'`,
			want: []string{"CzrMhR8zzy1eH1F0XlY1tu5ywqa2yaSFoWGg2cqE43XkfnUVCytnPQfv1enUYrzv", "Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK21a0LckgRSCL"},
		},
		{
			name:  "invalid pattern",
			input: "sumoId = 'doDkVYKjXZAwsz'",
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
