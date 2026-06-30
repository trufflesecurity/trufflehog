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
			name: "valid new format root token",
			data: `export VAULT_ROOT_TOKEN="hvs.CAESIJZm1j2kPxvbKIoZ8q5cN3bXKdXh"`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultRootToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "valid legacy format root token",
			data: `initial_root_token: s.1234567890abcdefghijklmn`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultRootToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "token in terraform config",
			data: `
vault_token = "hvs.CAESIN1hbXBsZXRva2VuZm9ydGVzdGluZ3B1cnBvc2Vz"
`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultRootToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid - too short",
			data:    `export TOKEN="hvs.short"`,
			want:    nil,
			wantErr: false,
		},
		{
			name:    "invalid - wrong prefix",
			data:    `export TOKEN="xyz.1234567890abcdefghijklmnopqrstuvwxyz"`,
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
					t.Errorf("VaultRootToken.FromData() result %d: Verified = %v, want %v (Raw: %s)",
						i, got[i].Verified, tt.want[i].Verified, string(got[i].Raw))
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
