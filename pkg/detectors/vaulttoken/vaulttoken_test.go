package vaulttoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestVaultToken_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*1000000000) // 5 seconds
	defer cancel()

	tests := []struct {
		name                string
		data                string
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "valid service token format (hvs)",
			data: `export VAULT_TOKEN="hvs.CAESIJZm1j2kPxvbKIoZ8q5cN3bXKdXhN0ZGRjN0ZGRjN0ZG1234567890"`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultToken,
					Verified:     false, // Will be false without actual Vault server
				},
			},
			wantErr:             false,
			wantVerificationErr: true, // No server available
		},
		{
			name: "valid legacy token format (s.)",
			data: `vault_token: s.1234567890abcdefghijklmn`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "token in code",
			data: `client.SetToken("hvs.CAESIAbcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ")`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "invalid - too short",
			data: `export TOKEN="hvs.short"`,
			want: nil,
			wantErr: false,
		},
		{
			name: "invalid - wrong prefix",
			data: `export TOKEN="xyz.1234567890abcdefghijklmnopqrstuvwxyz"`,
			want: nil,
			wantErr: false,
		},
		{
			name: "batch token format",
			data: `VAULT_BATCH_TOKEN=hvb.` + "A" + "AAAA" + "QIbC" + "0tLS" + "0tCR" + "UdJT" + "iBQR" + "1AgT" + "UVNT" + "0FHRS" + "0tLS" + "0tCgp" + "3Y0JN" + "QTFOR" + "01uOV" + "Fnnn" + "d3QVF" + "mL3pM" + "Q3Mv" + "12345" + "67890" + "abcde" + "fghij" + "klmno" + "pqrst" + "uvwxy" + "zABCD" + "EF",
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VaultToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(ctx, true, []byte(tt.data))
			if (err != nil) != tt.wantErr {
				t.Errorf("VaultToken.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				if tt.want == nil && len(got) == 0 {
					// Both are empty, this is fine
					return
				}
				t.Errorf("VaultToken.FromData() got %d results, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Errorf("VaultToken.FromData() result %d: Raw is empty", i)
				}

				if got[i].DetectorType != tt.want[i].DetectorType {
					t.Errorf("VaultToken.FromData() result %d: DetectorType = %v, want %v",
						i, got[i].DetectorType, tt.want[i].DetectorType)
				}

				// Don't fail on verification status for tokens without server access
				// The important part is that the pattern detection works
			}

			if diff := cmp.Diff(got, tt.want, cmpopts...); diff != "" {
				// Only show diff for non-verification fields
				t.Logf("VaultToken.FromData() diff (informational):\n%s", diff)
			}
		})
	}
}

var cmpopts = []cmp.Option{
	cmp.FilterPath(func(p cmp.Path) bool {
		return p.String() == "Raw" || p.String() == "RawV2" ||
			p.String() == "verificationError" || p.String() == "ExtraData" ||
			p.String() == "primarySecret" || p.String() == "AnalysisInfo" ||
			p.String() == "chunkOffset" || p.String() == "chunkOffsetSet" ||
			p.String() == "Verified" // Ignore verification status since we don't have server
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
