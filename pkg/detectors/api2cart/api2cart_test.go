package api2cart

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "0123456789abcdef0123456789abcdef"
	complexPattern = `
	To integrate with API2Cart, ensure you have the following credentials in your configuration file. Your API2CART key is 1234567890abcdef1234567890abcdef, which you will need to access the API securely. 

	The following endpoints are available for your use:
	- Get Products: https://api.api2cart.com/v1.0/products/get
	- Add Product: https://api.api2cart.com/v1.0/products/add
	`
	invalidPattern = "0123456789Gbcde^0123456789abcdef"
)

func TestApi2Cart_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("api2cart credentials: %s", validPattern),
			want:  []string{"0123456789abcdef0123456789abcdef"},
		},
		{
			name:  "valid pattern -complex",
			input: complexPattern,
			want:  []string{"1234567890abcdef1234567890abcdef"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("api2cart credentials: %s", invalidPattern),
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
