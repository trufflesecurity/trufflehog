package artifactoryreferencetoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestArtifactoryReferenceToken_Pattern(t *testing.T) {
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
			name: "valid pattern - environment variable",
			input: `
				[INFO] Connecting to Artifactory
				[DEBUG] Using reference token: cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtE
				[INFO] Connected to trufflehog.jfrog.io
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want: []string{
				"cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtEtrufflehog.jfrog.io",
			},
		},
		{
			name: "valid pattern - config file",
			input: `
				artifactory:
				  url: https://trufflehog.jfrog.io
				  reference_token: cmVmdGtuOjAxOjE3NjkxNjY0NjE6RE2ZeXpdsU1sOENUUG1RqXqDawNeMrJaTapu
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want: []string{
				"cmVmdGtuOjAxOjE3NjkxNjY0NjE6RE2ZeXpdsU1sOENUUG1RqXqDawNeMrJaTaputrufflehog.jfrog.io",
			},
		},
		{
			name: "valid pattern - curl command",
			input: `
				curl -H "Authorization: Bearer cmVmdGtuOjAxOjE3NzE0OTkzNzY6RG9OS0QxOHVLduRyyUtNrneMwqt6a33TNUZV" \
				  https://trufflehog.jfrog.io/artifactory/api/system/ping
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want: []string{
				"cmVmdGtuOjAxOjE3NzE0OTkzNzY6RG9OS0QxOHVLduRyyUtNrneMwqt6a33TNUZVtrufflehog.jfrog.io",
			},
		},
		{
			name: "valid pattern - with cloud endpoint",
			input: `
				[INFO] Connecting to Artifactory
				[DEBUG] Using reference token: cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtE
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtEcloudendpoint.jfrog.io",
			},
		},
		{
			name: "valid pattern - with cloud and found endpoints",
			input: `
				[INFO] Connecting to Artifactory
				[DEBUG] Using reference token: cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtE
				[INFO] trufflehog.jfrog.io
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: true,
			want: []string{
				"cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtEcloudendpoint.jfrog.io",
				"cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtEtrufflehog.jfrog.io",
			},
		},
		{
			name: "valid pattern - with disabled found endpoints",
			input: `
				[INFO] Connecting to Artifactory
				[DEBUG] Using reference token: cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtE
				[INFO] trufflehog.jfrog.io
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtEcloudendpoint.jfrog.io",
			},
		},
		{
			name: "valid pattern - with https in configured endpoint",
			input: `
				[INFO] Connecting to Artifactory
				[DEBUG] Using reference token: cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtE
				[INFO] Response received: 200 OK
			`,
			cloudEndpoint:    "https://cloudendpoint.jfrog.io",
			useCloudEndpoint: true,
			useFoundEndpoint: false,
			want: []string{
				"cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtEcloudendpoint.jfrog.io",
			},
		},
		{
			name: "finds multiple tokens",
			input: `
				# Primary token
				export ARTIFACTORY_TOKEN=cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtE
				# Backup token
				export ARTIFACTORY_TOKEN_BACKUP=cmVmdGtuOjAxOjE3NjkxNjY0NjE6RE2ZeXpdsU1sOENUUG1RqXqDawNeMrJaTapu
				export ARTIFACTORY_URL=https://trufflehog.jfrog.io
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want: []string{
				"cmVmdGtuOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtEtrufflehog.jfrog.io",
				"cmVmdGtuOjAxOjE3NjkxNjY0NjE6RE2ZeXpdsU1sOENUUG1RqXqDawNeMrJaTaputrufflehog.jfrog.io",
			},
		},
		{
			name: "invalid pattern - too short",
			input: `
				[DEBUG] Using token: cmVmdGtuOjAxOjAwMDAwMDAwMDA6SHORT
				[INFO] URL: trufflehog.jfrog.io
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want:             nil,
		},
		{
			name: "invalid pattern - wrong prefix",
			input: `
				[DEBUG] Using token: aBcDeFgHOjAxOjAwMDAwMDAwMDA6awJQVlZkdEVyWXJ2cVNSemAABVQ1bwaBSWtE
				[INFO] URL: trufflehog.jfrog.io
			`,
			useCloudEndpoint: false,
			useFoundEndpoint: true,
			want:             nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Configure endpoint customizer based on test case
			d.UseFoundEndpoints(test.useFoundEndpoint)
			d.UseCloudEndpoint(test.useCloudEndpoint)
			if test.useCloudEndpoint && test.cloudEndpoint != "" {
				d.SetCloudEndpoint(test.cloudEndpoint)
			}

			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf("keywords were not matched: %v", d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
				for _, r := range results {
					t.Logf("got: %s", string(r.RawV2))
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
