package rancher

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "RANCHER_URL=https://rancher.example.com\nRANCHER_API_TOKEN=kubeadmin5f8a3b2c1d9e4f7a6b0c5d2e8f1a4b7c3d6e9f2a5b8c1d4e7f0a3b6"
	invalidPattern = "RANCHER_API_TOKEN=shorttoken123"
	keyword        = "rancher_api_token"
)

func TestRancher_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern with server context",
			input: fmt.Sprintf("%s", validPattern),
			want:  []string{"kubeadmin5f8a3b2c1d9e4f7a6b0c5d2e8f1a4b7c3d6e9f2a5b8c1d4e7f0a3b6"},
		},
		{
			name:  "invalid pattern - token too short",
			input: fmt.Sprintf("%s token = '%s'", keyword, invalidPattern),
			want:  []string{},
		},
		{
			name:  "no server context - should not detect",
			input: "RANCHER_API_TOKEN=kubeadmin5f8a3b2c1d9e4f7a6b0c5d2e8f1a4b7c3d6e9f2a5b8c1d4e7f0a3b6",
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

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
