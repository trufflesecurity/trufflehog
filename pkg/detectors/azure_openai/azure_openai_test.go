//go:build detectors
// +build detectors

package azure_openai

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
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
# {'X-OpenAI-Client-User-Agent': '{"bindings_version": "0.27.6", "httplib": "requests", "lang": "python", "lang_version": "3.11.2", "platform": "macOS-13.2-arm64-arm-64bit", "publisher": "openai", "uname": "Darwin 22.3.0 Darwin Kernel Version 22.3.0: Thu Jan  5 20:48:54 PST 2023; root:xnu-8792.81.2~2/RELEASE_ARM64_T6000 arm64 arm"}', 'User-Agent': 'OpenAI/v1 PythonBindings/0.27.6', 'api-key': '49eb7c2d3acd41f4ac31fef59ceacbba', 'OpenAI-Debug': 'true', 'Content-Type': 'application/json'}`,
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chunkSpecificDetectors := make(map[ahocorasick.DetectorKey]detectors.Detector, 2)
			ahoCorasickCore.PopulateMatchingDetectors(test.input, chunkSpecificDetectors)
			if len(chunkSpecificDetectors) == 0 {
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

func TestAzureOpenAI_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("AZUREOPENAI")
	inactiveSecret := testSecrets.MustGetField("AZUREOPENAI_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a azureopenai secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_AzureOpenAI,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a azureopenai secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_AzureOpenAI,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a azureopenai secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_AzureOpenAI,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a azureopenai secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_AzureOpenAI,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Azureopenai.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Azureopenai.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
