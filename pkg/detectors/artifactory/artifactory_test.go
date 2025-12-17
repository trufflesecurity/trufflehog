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
				[DEBUG] Using Key=cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want:             []string{"cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZgrwxtOp.jfrog.io"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{artifactory}</id>
  					<secret>{AQAAABAAA KUd8GOVfcXnIv1nJ5qmnNzrqkLvseoPRMuwsdDVr9QthonFogtMaoJ3pgtO4eHXC}</secret>
					<domain>{HTTPnGQZ79vjWXze.jfrog.io}</domain>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want:             []string{"KUd8GOVfcXnIv1nJ5qmnNzrqkLvseoPRMuwsdDVr9QthonFogtMaoJ3pgtO4eHXCHTTPnGQZ79vjWXze.jfrog.io"},
		},
		{
			name: "valid pattern - with cloud endpoints",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want:             []string{"cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZgcloudendpoint.jfrog.io"},
		},
		{
			name: "valid pattern - with cloud and found endpoints",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: true,
			want: []string{
				"cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZgcloudendpoint.jfrog.io",
				"cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZgrwxtOp.jfrog.io",
			},
		},
		{
			name: "valid pattern - with disabled found endpoints",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZgcloudendpoint.jfrog.io",
			},
		},
		{
			name: "valid pattern - with https in configured endpoint",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "https://cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZgcloudendpoint.jfrog.io",
			},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Using Key=cmVmdGtuOjAxOjEODA_1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				[INFO] rwxtOp.jfrog.io
				[INFO] Response received: 200 OK
			`,
			useFoundEndpoint: true,
			want:             nil,
		},
		{
			name: "valid pattern - basic auth uri",
			input: `https://user123:ATBB123abcDEF456ghiJKL789mnoPQR@test.jfrog.io/artifactory/api/pypi/pypi/simple`,
			cloudEndpoint:    "https://cloudendpoint.jfrog.io",
			useCloudEndpoint: false,
			useFoundEndpoint: false,
			want:  []string{"user123:ATBB123abcDEF456ghiJKL789mnoPQR@test.jfrog.io"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// this detector use endpoint customizer interface so we need to enable them based on test case
			d.UseFoundEndpoints(test.useFoundEndpoint)
			d.UseCloudEndpoint(test.useCloudEndpoint)
			// if test case provide cloud endpoint use it
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
