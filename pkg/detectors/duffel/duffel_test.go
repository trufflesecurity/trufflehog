package duffel

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestDuffel_FromChunk(t *testing.T) {
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
			name: "valid test token",
			data: `export DUFFEL_TOKEN="duffel_test_1234567890abcdefghijklmnopqrstuvwxyz1234567890"`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Duffel,
					Verified:     false, // Will be true with actual token
				},
			},
			wantErr: false,
		},
		{
			name: "valid test token in code",
			data: `const duffelClient = new Duffel({
				token: 'duffel_test_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
			});`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Duffel,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "valid live token - should not verify",
			data: `DUFFEL_API_KEY=duffel_live_1234567890abcdefghijklmnopqrstuvwxyz1234567890`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Duffel,
					Verified:     false, // Live tokens are not auto-verified
				},
			},
			wantErr:             false,
			wantVerificationErr: true, // Should have verification error (live token skipped)
		},
		{
			name: "invalid pattern - too short",
			data: `export TOKEN="duffel_test_short"`,
			want: nil,
			wantErr: false,
		},
		{
			name: "invalid pattern - wrong prefix",
			data: `export TOKEN="duffel_prod_1234567890abcdefghijklmnopqrstuvwxyz1234567890"`,
			want: nil,
			wantErr: false,
		},
		{
			name: "multiple tokens",
			data: `
				const testToken = "duffel_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
				const liveToken = "duffel_live_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
			`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Duffel,
					Verified:     false,
				},
				{
					DetectorType: detector_typepb.DetectorType_Duffel,
					Verified:     false,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(ctx, true, []byte(tt.data))
			if (err != nil) != tt.wantErr {
				t.Errorf("Duffel.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("Duffel.FromData() got %d results, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Errorf("Duffel.FromData() result %d: Raw is empty", i)
				}

				if got[i].DetectorType != tt.want[i].DetectorType {
					t.Errorf("Duffel.FromData() result %d: DetectorType = %v, want %v",
						i, got[i].DetectorType, tt.want[i].DetectorType)
				}

				if got[i].Verified != tt.want[i].Verified {
					t.Errorf("Duffel.FromData() result %d: Verified = %v, want %v (Raw: %s)",
						i, got[i].Verified, tt.want[i].Verified, string(got[i].Raw))
				}

				if tt.wantVerificationErr {
					if got[i].VerificationError() == nil {
						t.Errorf("Duffel.FromData() result %d: expected verification error but got none", i)
					}
				}
			}

			if diff := cmp.Diff(got, tt.want, cmpopts...); diff != "" {
				t.Errorf("Duffel.FromData() diff (-got +want):\n%s", diff)
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
