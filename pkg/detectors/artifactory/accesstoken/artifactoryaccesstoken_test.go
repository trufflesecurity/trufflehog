package artifactory

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestArtifactory_Pattern(t *testing.T) {
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
			name: "valid pattern",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want: []string{
				"AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE" +
					"rwxtOp.jfrog.io",
			},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{artifactory}</id>
  					<secret>AKCp8budTFpbypBqQbGJPp7eHFi28fBivfWczrjbPb9erDff9LbXZbj6UsRExVXA8asWGc9fM</secret>
					<domain>{HTTPnGQZ79vjWXze.jfrog.io}</domain>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want: []string{
				"AKCp8budTFpbypBqQbGJPp7eHFi28fBivfWczrjbPb9erDff9LbXZbj6UsRExVXA8asWGc9fM" +
					"HTTPnGQZ79vjWXze.jfrog.io",
			},
		},
		{
			name: "valid pattern - with cloud endpoints",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE" +
					"cloudendpoint.jfrog.io",
			},
		},
		{
			name: "valid pattern - with cloud and found endpoints",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: true,
			want: []string{
				"AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE" +
					"cloudendpoint.jfrog.io",
				"AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE" +
					"rwxtOp.jfrog.io",
			},
		},
		{
			name: "valid pattern - with disabled found endpoints",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE" +
					"cloudendpoint.jfrog.io",
			},
		},
		{
			name: "valid pattern - with https in configured endpoint",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "https://cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE" +
					"cloudendpoint.jfrog.io",
			},
		},
		{
			name: "invalid pattern - wrong prefix",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=XYZp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmdsY8ghxFGgehZcK3UGNgy5TxHWdE
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			useFoundEndpoint: true,
			want:             nil,
		},
		{
			name: "invalid pattern - too short",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=AKCp5e2gMx8TtJNDtrsuPq7Jz24Rqjkjf1d1iiy1GuEjmd
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			useFoundEndpoint: true,
			want:             nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// this detector uses endpoint customizer interface so we need to enable them based on test case
			d.UseFoundEndpoints(test.useFoundEndpoint)
			d.UseCloudEndpoint(test.useCloudEndpoint)
			// if the test case provides cloud endpoint, then use it
			if test.useCloudEndpoint && test.cloudEndpoint != "" {
				d.SetCloudEndpoint(test.cloudEndpoint)
			}

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
