package cloudinary

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCloudinary_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] Sending request to the API
				[DEBUG] Using cloudinary_apiSecret=ndiawudh1_wdajwoidjajawdeps
				[DEBUG] Using cloudinary_apiKey=218873249723411
				[DEBUG] Using cloudinary_cloudName=wdjaiwojd
				[INFO] Response received: 200 OK
			`,
			want: []string{"wdjaiwojd" + ":" + "218873249723411" + ":" + "ndiawudh1_wdajwoidjajawdeps"},
		},
		{
			name: "valid pattern - cloudinary api environment variable",
			input: `
				[INFO] Sending request to the cloudinary 
				[DEBUG] Using url=cloudinary://715268876851676:V-fwwRhcp3VrRPAqaFkLq3rpa60@fakwfpoaj
				[INFO] Response received: 200 OK
			`,
			want: []string{"fakwfpoaj" + ":" + "715268876851676" + ":" + "V-fwwRhcp3VrRPAqaFkLq3rpa60"},
		},

		{
			name: "valid pattern - out of prefix range - apikey",
			input: `
				[INFO] Sending request to the cloudinary
				[DEBUG] Using cloudName=wdjaiwojd
				[DEBUG] Using cloudinary_apiSecret=ndiawudh1_wdajwoidjajawdeps
				[DEBUG] apiKey=218873249723411 
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "valid pattern - out of prefix range - apiSecret",
			input: `
				[INFO] Sending request to the cloudinary
				[DEBUG]	Using cloudName=wdjaiwojd
				[DEBUG] apiKey=218873249723411 
				[DEBUG] Using apiSecret=ndiawudh1_wdajwoidjajawdeps
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "valid pattern - out of prefix range - cloudName",
			input: `
				[INFO] Sending request to the cloudinary
				[DEBUG] apiKey=218873249723411 
				[DEBUG] Using apiSecret=ndiawudh1_wdajwoidjajawdeps
				[INFO] 	Response received: 200 OK
				[DEBUG] Used cloudName=wdjaiwojd
			`,
			want: nil,
		},
		{
			name: "valid pattern - only apikey",
			input: `
				[INFO] Sending request to the cloudinary API
				[DEBUG] Using apiKey=218873249723411 
			`,
			want: nil,
		},
		{
			name: "valid pattern - only secret",
			input: `
				[INFO] Sending request to the cloudinary API
				[DEBUG] Using apiSecret=ndiawudh1_wdajwoidjajawdeps
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "valid pattern - only cloudName",
			input: `
				[INFO] Sending request to the cloudinary API
				[DEBUG] Using cloudName=wdjaiwojd
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid api key length",
			input: `
				[INFO] Sending request to the cloudinary API
				[DEBUG] Using apikey=12312312432541444
				[DEBUG] Using apiSecret=ndiawudh1_wdajwoidjajawdeps
				[DEBUG]	Using cloudName=wdjaiwojd
				[ERROR] Response received: 400 BadRequest
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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
