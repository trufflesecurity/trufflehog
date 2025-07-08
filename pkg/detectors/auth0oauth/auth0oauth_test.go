package auth0oauth

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
	auth0_credentials file: 
		auth0_clientID: kYWr_tL4eYBtqIIvKfSf2-e4T9Cw1CtwE8ufoESVBB7Hi1U
		secret: rXwGtKCleBsaUfpchggQEAy_yhzWnqv4_GzJivBif85bqiJi3ZA63DAauoJ2PF27fvS-MBqIYgxH0vZaL1s5314lgPDLqHXjZsY59PSew63A_L6rySqcy5J3rFcGcpdeSQ_tTx1kCXOZY_JUy 
		domain: 9-KhTIdSopSaMQ2v1YxdFEJN-HNgt7Mn7E8xkfQNqd51AzSGQu2yRaFauth0.com
	`
	invalidPattern = `
	auth0_credentials file: 
		auth0_clientID: e4T9Cw1CtwE8ufoESVBB7Hi1U-e4T9Cw1CtwE8ufoESVBB7Hi1U
		secret: MBqIYgxH0vZaL1s5314lgPDLqHX^ZsY59PSew63A_L6rySqcy5J3rFcGcpdeSQ_+tTx1kCXOZY_JUy-rXwGtKCleBsaUfpchggQEAy_yhzWnqv4_GzJivBif85bqiJi3ZA63DAauoJ2PF27fvS 
		domain: 9-KhTIdSopSaMQ2v1YxdFEJN#qd51AzSGQu2yRaFauth1.com
	`
)

func TestAuth0oAuth_Pattern(t *testing.T) {
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
			want:  []string{"kYWr_tL4eYBtqIIvKfSf2-e4T9Cw1CtwE8ufoESVBB7Hi1UrXwGtKCleBsaUfpchggQEAy_yhzWnqv4_GzJivBif85bqiJi3ZA63DAauoJ2PF27fvS-MBqIYgxH0vZaL1s5314lgPDLqHXjZsY59PSew63A_L6rySqcy5J3rFcGcpdeSQ_tTx1kCXOZY_JUy"},
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
