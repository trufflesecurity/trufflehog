package artifactory

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

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
				# artifactory credentials
				Token: cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				Url: rwxtOp.jfrog.io
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want:             []string{"cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZgrwxtOp.jfrog.io"},
		},
		{
			name: "valid pattern - with cloud endpoints",
			input: `
				# artifactory credentials
				Token: cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want:             []string{"cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZgcloudendpoint.jfrog.io"},
		},
		{
			name: "valid pattern - with cloud and found endpoints",
			input: `
				# artifactory credentials
				Token: cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				Url: rwxtOp.jfrog.io
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
				# artifactory credentials
				Token: cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				Url: rwxtOp.jfrog.io
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
				# artifactory credentials
				Token: cmVmdGtuOjAxOjE3ODA1NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
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
				# artifactory credentials
				Token: cmVmdGtuOjAxOjE3ODA_NTFAKEM6S2J2MGswemNzZzhaRnFlVUFAKEk3amlLcGZg
				Url: rwxtOp.jfroq.io
			`,
			useFoundEndpoint: true,
			want:             nil,
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
