package makeapitoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestMakeApiToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name             string
		input            string
		cloudEndpoint    string
		useCloudEndpoint bool
		useFoundEndpoint bool
		want             []string
	}{
		{
			name: "valid pattern with found endpoint",
			input: `
				# make api token
				MAKE_TOKEN: bbb94d50-239f-4609-9569-63ea15eb0996
				URL: https://eu1.make.com/api/v2/
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want:             []string{"bbb94d50-239f-4609-9569-63ea15eb0996:eu1.make.com"},
		},
		{
			name: "valid pattern with configured endpoint",
			input: `
				# make.com api token
				MAKE_TOKEN: bbb94d50-239f-4609-9569-63ea15eb0996
			`,
			cloudEndpoint:    "us1.make.com",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want:             []string{"bbb94d50-239f-4609-9569-63ea15eb0996:us1.make.com"},
		},
		{
			name: "valid pattern with both found and configured endpoints",
			input: `
				# make api token
				MAKE_TOKEN: bbb94d50-239f-4609-9569-63ea15eb0996
				URL: https://eu1.make.com/api/v2/
			`,
			cloudEndpoint:    "us1.make.com",
			useCloudEndpoint: true,
			useFoundEndpoint: true,
			want: []string{
				"bbb94d50-239f-4609-9569-63ea15eb0996:us1.make.com",
				"bbb94d50-239f-4609-9569-63ea15eb0996:eu1.make.com",
			},
		},
		{
			name: "valid pattern with disabled found endpoints",
			input: `
				# make api token
				MAKE_TOKEN: bbb94d50-239f-4609-9569-63ea15eb0996
				URL: https://eu1.make.com/api/v2/
			`,
			cloudEndpoint:    "us1.make.com",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"bbb94d50-239f-4609-9569-63ea15eb0996:us1.make.com",
			},
		},
		{
			name: "valid pattern with celonis domain",
			input: `
				# make api token
				MAKE_TOKEN: bbb94d50-239f-4609-9569-63ea15eb0996
				URL: us1.make.celonis.com
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want: []string{
				"bbb94d50-239f-4609-9569-63ea15eb0996:us1.make.celonis.com",
			},
		},
		{
			name: "no endpoints configured or found",
			input: `
				# make.com api token
				MAKE_TOKEN: bbb94d50-239f-4609-9569-63ea15eb0996
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: false,
			want:             nil,
		},
		{
			name: "duplicate endpoints deduplicated",
			input: `
				# make api token with duplicate endpoints
				MAKE_TOKEN: bbb94d50-239f-4609-9569-63ea15eb0996
				URL: us1.make.com
				URL: us1.make.com
				URL: us1.make.com
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want: []string{
				"bbb94d50-239f-4609-9569-63ea15eb0996:us1.make.com",
			},
		},
		{
			name: "invalid pattern",
			input: `
				# make.com api token
				MAKE_TOKEN: invalid-token-format
			`,
			useFoundEndpoint: true,
			want:             nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Configure the detector based on test case
			d.UseFoundEndpoints(test.useFoundEndpoint)
			d.UseCloudEndpoint(test.useCloudEndpoint)
			if test.useCloudEndpoint && test.cloudEndpoint != "" {
				d.SetCloudEndpoint(test.cloudEndpoint)
			}

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
