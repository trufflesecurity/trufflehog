//go:build detectors
// +build detectors

package npm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestNpmTokenV2_Pattern(t *testing.T) {
	tests := map[string]npmPatternTestCase{
		"no_context": {
			input:    `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`,
			expected: "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",
		},
		".npmrc": {
			input:    `//registry.npmjs.org/:_authToken=npm_ZAQB7VuVmml1pMGorDFwyeEpuQrA8I4ypgPF`,
			expected: "npm_ZAQB7VuVmml1pMGorDFwyeEpuQrA8I4ypgPF",
		},
		"yaml_spec": {
			input: `    - env:
        NPM_TOKEN: npm_tCEMceczuiTXKQaBjGIaAezYQ63PqI972ANG`,
			expected: "npm_tCEMceczuiTXKQaBjGIaAezYQ63PqI972ANG",
		},
		"bashrc": {
			input:    `export NPM_TOKEN=npm_ySTLJHpS9DCwByClZBMyqRWptr2kB40hEjiS`,
			expected: "npm_ySTLJHpS9DCwByClZBMyqRWptr2kB40hEjiS",
		},

		// Invalid
		"invalid/placeholder_0": {
			input: `   //registry.npmjs.org/:_authToken=npm_000000000000000000000000000000000000`,
		},
		"invalid/placeholder_x": {
			input: `//registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		},
		"invalid/word_boundary": {
			input: `    "image_small_url": "https://c10.patreonusercontent.com/3/eyJoIjo2NDAsInYiOiIzIiwidyI6NjQwfQ%3D%3D/patreon-media/campaign/1493621/91a5dc5347a741af89aaed35d2a82b5c?token-time=2145916800\u0026token-hash=Qznpm_uHiQAba4K3HTRZjrhQei4dU0tmZbaavLrM2FY%3D",`,
		},
		"invalid/uppercase": {
			input: `"operationId": "Npm_GetScopedPackageVersionFromRecycleBin",`,
		},
	}

	testPattern(t, ScannerV2{}, tests)
}

func TestNpmTokenV2_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("NPM_TOKEN_V2")
	inactiveSecret := testSecrets.MustGetField("NPM_TOKEN_V2_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		s       ScannerV2
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "found, verified",
			s:    ScannerV2{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a NpmTokenV2 secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NpmToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    ScannerV2{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a NpmTokenV2 secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NpmToken,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    ScannerV2{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScannerV2{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NpmTokenV2.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("NpmTokenV2.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromDataV2(benchmark *testing.B) {
	ctx := context.Background()
	s := ScannerV2{}
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
