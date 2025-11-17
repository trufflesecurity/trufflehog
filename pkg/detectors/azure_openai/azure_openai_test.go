package azure_openai

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureOpenAI_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "Generic environment variables",
			input: `export OPENAI_API_VERSION=2023-07-15-preview
					export OPENAI_API_TYPE=AZURE
					export OPENAI_API_BASE=https://james-test-gpt4.openai.azure.com/
					export OPENAI_API_KEY=3397348fcdcb4a5fbeb6cceb5a6a284f`,
			want: []string{"3397348fcdcb4a5fbeb6cceb5a6a284f"},
		},
		{
			name: "Generic non-structured",
			input: `# {'input': ['This is a test query.'], 'engine': 'text-embedding-ada-002'}
					# url /openai/deployments/text-embedding-ada-002/embeddings?api-version=2022-12-01
					# params {'input': ['This is a test query.'], 'encoding_format': 'base64'}
					# headers None
					# message='Request to OpenAI API' method=post path=https://notebook-openai01.openai.azure.com/openai/deployments/text-embedding-ada-002/embeddings?api-version=2022-12-01
					# api_version=2022-12-01 data='{"input": ["This is a test query."], "encoding_format": "base64"}' message='Post details'
					# https://notebook-openai01.openai.azure.com/openai/deployments/text-embedding-ada-002/embeddings?api-version=2022-12-01
					# {'X-OpenAI-Client-User-Agent': '{"bindings_version": "0.27.6", "httplib": "requests", "lang": "python", "lang_version": "3.11.2", "platform": "macOS-13.2-arm64-arm-64bit",
					"publisher": "openai", "uname": "Darwin 22.3.0 Darwin Kernel Version 22.3.0: Thu Jan  5 20:48:54 PST 2023; root:xnu-8792.81.2~2/RELEASE_ARM64_T6000 arm64 arm"}', 'User-Agent': 'OpenAI/v1 PythonBindings/0.27.6', 'api-key': '49eb7c2d3acd41f4ac31fef59ceacbba', 'OpenAI-Debug': 'true', 'Content-Type': 'application/json'}`,
			want: []string{"49eb7c2d3acd41f4ac31fef59ceacbba"},
		},
		{
			name: "Python",
			input: `import openai

			openai.api_key = '1bb7dff73fe449de829363ea03bab134'
			openai.api_base = "https://hrcop-openai.openai.azure.com/"
			`,
			want: []string{"1bb7dff73fe449de829363ea03bab134"},
		},
		{
			name: "Python environment variables",
			input: `os.environ["OPENAI_API_TYPE"] = "azure"
					os.environ["OPENAI_API_VERSION"] = "2023-03-15-preview"
					os.environ["OPENAI_API_BASE"] = "https://superhackathonai101-openai.openai.azure.com/"
					os.environ["OPENAI_API_KEY"] = '1bb7dde73fe449de229361ea03bab234'`,
			want: []string{"1bb7dde73fe449de229361ea03bab234"},
		},
		{
			name: "TypeScript",
			input: `import OpenAI from "openai";
					export const openai = new OpenAI({
					apiKey: "3375e3ad9a874cd6bd954b6f163be84f",
					baseURL:
						"https://kumar-azure.openai.azure.com/openai/deployments/ChatAutoUpdate",
					defaultQuery: { "api-version": "2023-06-01-preview" },
					});`,
			want: []string{"3375e3ad9a874cd6bd954b6f163be84f"},
		},
		{
			name: "OpenAi key name",
			input: `{
					"IsEncrypted": false,
					"Values": {
						"AZURE_OPENAI_ENDPOINT": "https://bcdemo-openai.openai.azure.com/",
						"AZURE_OPENAI_KEY": "57d2de35873840b5ad59d742e90e974e"
					}
					}`,
			want: []string{"57d2de35873840b5ad59d742e90e974e"},
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
