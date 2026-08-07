package vaultroottoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestVaultRootToken_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*1000000000) // 5 seconds
	defer cancel()

	tests := []struct {
		name    string
		data    string
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "valid hvs root token in init output",
			data: `Initial Root Token: hvs.CAESIAbcdefghijklmnopqrstuvwxyz1234567890`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultRootToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "valid legacy root token in env var",
			data: `VAULT_ROOT_TOKEN=s.abcdefghijklmnopqrstuvwxyz123456`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultRootToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name:    "token without root context not detected",
			data:    `export VAULT_TOKEN="hvs.CAESIAbcdefghijklmnopqrstuvwxyz1234567890"`,
			want:    nil,
			wantErr: false,
		},
		{
			name:    "invalid short root token",
			data:    `root_token: s.short`,
			want:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(ctx, true, []byte(tt.data))
			if (err != nil) != tt.wantErr {
				t.Errorf("VaultRootToken.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				if tt.want == nil && len(got) == 0 {
					return
				}
				t.Errorf("VaultRootToken.FromData() got %d results, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Errorf("VaultRootToken.FromData() result %d: Raw is empty", i)
				}

				if got[i].DetectorType != tt.want[i].DetectorType {
					t.Errorf("VaultRootToken.FromData() result %d: DetectorType = %v, want %v",
						i, got[i].DetectorType, tt.want[i].DetectorType)
				}

				if got[i].Verified != tt.want[i].Verified {
					t.Errorf("VaultRootToken.FromData() result %d: Verified = %v, want %v",
						i, got[i].Verified, tt.want[i].Verified)
				}
			}

			if diff := cmp.Diff(got, tt.want, cmpopts...); diff != "" {
				t.Logf("VaultRootToken.FromData() diff (informational):\n%s", diff)
			}
		})
	}
}

var cmpopts = []cmp.Option{
	cmp.FilterPath(func(p cmp.Path) bool {
		return p.String() == "Raw" || p.String() == "RawV2" ||
			p.String() == "verificationError" || p.String() == "ExtraData" ||
			p.String() == "primarySecret" || p.String() == "AnalysisInfo" ||
			p.String() == "chunkOffset" || p.String() == "chunkOffsetSet"
	}, cmp.Ignore()),
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
