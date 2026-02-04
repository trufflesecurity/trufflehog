package gitlaboauth2

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestGitlabOauth_Pattern(t *testing.T) {
	d := Scanner{}
	d.SetCloudEndpoint("https://gitlab.com")
	d.UseCloudEndpoint(true)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - client_id and client_secret",
			input: `
				gitlab:
				  client_id: 04fcf956cb6c5f4b106f3a4eca76eaf70e8c5d07a976ecf3baff9ac778a0098a
				  client_secret: gloas-8406980541370e5bd4f04c5da232c2cdabe7fa3959eb1757eeef7299e2458216
			`,
			want: []string{"04fcf956cb6c5f4b106f3a4eca76eaf70e8c5d07a976ecf3baff9ac778a0098agloas-8406980541370e5bd4f04c5da232c2cdabe7fa3959eb1757eeef7299e2458216https://gitlab.com"},
		},
		{
			name: "valid pattern - application_id prefix",
			input: `
				GITLAB_APPLICATION_ID=99f0b46fc9241b7fa4b7d567044fab74a5f00ac0f12244ccfed1ea67d4a975df
				GITLAB_SECRET=gloas-35fa9094e834aafb153bc17f1a31f48071af915c2ccf2f890b6714b954896321
			`,
			want: []string{"99f0b46fc9241b7fa4b7d567044fab74a5f00ac0f12244ccfed1ea67d4a975dfgloas-35fa9094e834aafb153bc17f1a31f48071af915c2ccf2f890b6714b954896321https://gitlab.com"},
		},
		{
			name: "valid pattern - JSON format",
			input: `
				{
					"app_id": "763c4e64f4c40dd070010617639cc11e37bbaf1a798503dd96ee5e6852754862",
					"secret": "gloas-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
				}
			`,
			want: []string{"763c4e64f4c40dd070010617639cc11e37bbaf1a798503dd96ee5e6852754862gloas-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefhttps://gitlab.com"},
		},
		{
			name: "multiple matches",
			input: `
				# Production
				client_id: 04fcf956cb6c5f4b106f3a4eca76eaf70e8c5d07a976ecf3baff9ac778a0098a
				client_secret: gloas-8406980541370e5bd4f04c5da232c2cdabe7fa3959eb1757eeef7299e2458216

				# Staging
				client_id: 99f0b46fc9241b7fa4b7d567044fab74a5f00ac0f12244ccfed1ea67d4a975df
				client_secret: gloas-35fa9094e834aafb153bc17f1a31f48071af915c2ccf2f890b6714b954896321
			`,
			want: []string{
				"04fcf956cb6c5f4b106f3a4eca76eaf70e8c5d07a976ecf3baff9ac778a0098agloas-8406980541370e5bd4f04c5da232c2cdabe7fa3959eb1757eeef7299e2458216https://gitlab.com",
				"04fcf956cb6c5f4b106f3a4eca76eaf70e8c5d07a976ecf3baff9ac778a0098agloas-35fa9094e834aafb153bc17f1a31f48071af915c2ccf2f890b6714b954896321https://gitlab.com",
				"99f0b46fc9241b7fa4b7d567044fab74a5f00ac0f12244ccfed1ea67d4a975dfgloas-8406980541370e5bd4f04c5da232c2cdabe7fa3959eb1757eeef7299e2458216https://gitlab.com",
				"99f0b46fc9241b7fa4b7d567044fab74a5f00ac0f12244ccfed1ea67d4a975dfgloas-35fa9094e834aafb153bc17f1a31f48071af915c2ccf2f890b6714b954896321https://gitlab.com",
			},
		},
		{
			name: "invalid pattern - wrong secret prefix",
			input: `
				client_id: 04fcf956cb6c5f4b106f3a4eca76eaf70e8c5d07a976ecf3baff9ac778a0098a
				client_secret: glpat-8406980541370e5bd4f04c5da232c2cdabe7fa3959eb1757eeef7299e2458216
			`,
			want: []string{},
		},
		{
			name: "invalid pattern - secret too short",
			input: `
				client_id: 04fcf956cb6c5f4b106f3a4eca76eaf70e8c5d07a976ecf3baff9ac778a0098a
				client_secret: gloas-8406980541370e5bd4f04c5da232c2cd
			`,
			want: []string{},
		},
		{
			name: "invalid pattern - client_id too short",
			input: `
				client_id: 04fcf956cb6c5f4b106f3a4eca76eaf7
				client_secret: gloas-8406980541370e5bd4f04c5da232c2cdabe7fa3959eb1757eeef7299e2458216
			`,
			want: []string{},
		},
		{
			name: "invalid pattern - no client_id context prefix",
			input: `
				04fcf956cb6c5f4b106f3a4eca76eaf70e8c5d07a976ecf3baff9ac778a0098a
				gloas-8406980541370e5bd4f04c5da232c2cdabe7fa3959eb1757eeef7299e2458216
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords were not matched: %v", d.Keywords())
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
