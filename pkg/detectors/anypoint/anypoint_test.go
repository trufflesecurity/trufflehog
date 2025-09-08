package anypoint

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAnypoint_Pattern(t *testing.T) {
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
				# Anypoint Secret Configuration File
				# Organization details
				ORG_NAME=my_organization
				ORG_ID=abcd1234-ef56-gh78-ij90-klmn1234opqr

				# OAuth tokens
				ACCESS_TOKEN=abcxyz123
				REFRESH_TOKEN=zyxwvutsrqponmlkji9876543210abcd

				# API keys
				SECRET_KEY=1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6

				# Endpoints
				SERVICE_URL=https://api.example.com/v1/resource
				`,
			want: []string{"1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6abcd1234-ef56-gh78-ij90-klmn1234opqr"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{anypoint org rdogw4dd-6x3l-2nm3-jvl5-qi8dyheccgj7}</id>
  					<secret>{AQAAABAAA 7jhlugw8-3tfb-7ju2-0i0y-7un6qxvknbvz}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"7jhlugw8-3tfb-7ju2-0i0y-7un6qxvknbvzrdogw4dd-6x3l-2nm3-jvl5-qi8dyheccgj7"},
		},
		{
			name: "invalid pattern",
			input: `
				# Anypoint Secret Configuration File
				# Organization details
				ORG_NAME=my_organization
				ORG_ID=abcd1234-ef56-gh78-ij90-klmn1234opqr

				# OAuth tokens
				ACCESS_TOKEN=abcxyz123
				REFRESH_TOKEN=zyxwvutsrqponmlkji9876543210abcd

				# API keys
				SECRET_KEY=1a2b3C4d-5E6f-7g8H-9i0J-k1l2M3n4o5p6

				# Endpoints
				SERVICE_URL=https://api.example.com/v1/resource
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
