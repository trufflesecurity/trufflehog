package dockerswarmunlock

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestDockerSwarmUnlock_FromChunk(t *testing.T) {
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
			name: "valid unlock key",
			data: `export SWARM_UNLOCK_KEY="SWMKEY-1-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOp"`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_DockerSwarmUnlock,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "valid unlock key in docker command",
			data: "docker swarm unlock\nTo unlock a swarm manager after it restarts, run the docker swarm unlock\ncommand and provide the following key:\n\n    SWMKEY-1-ZnR0YWJiZXJfcmFuZG9tX2RhdGFfZm9yX3Rlc3RpbmdfcHVycG9zZXM=\n\nPlease remember to store this key in a password manager.",
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_DockerSwarmUnlock,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid pattern - no prefix",
			data: `export KEY="1-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOp"`,
			want: []detectors.Result{},
			wantErr: false,
		},
		{
			name: "invalid pattern - wrong prefix",
			data: `export KEY="SWARM-1-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOp"`,
			want: []detectors.Result{},
			wantErr: false,
		},
		{
			name: "valid pattern with base64 padding",
			data: `SWMKEY-1-VGhpc0lzQVRlc3RLZXlXaXRoUGFkZGluZ1RvRGVtb25zdHJhdGU==`,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_DockerSwarmUnlock,
					Verified:     true,
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
				t.Errorf("DockerSwarmUnlock.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("DockerSwarmUnlock.FromData() got %d results, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Errorf("DockerSwarmUnlock.FromData() result %d: Raw is empty", i)
				}

				if got[i].DetectorType != tt.want[i].DetectorType {
					t.Errorf("DockerSwarmUnlock.FromData() result %d: DetectorType = %v, want %v",
						i, got[i].DetectorType, tt.want[i].DetectorType)
				}

				if got[i].Verified != tt.want[i].Verified {
					t.Errorf("DockerSwarmUnlock.FromData() result %d: Verified = %v, want %v (Raw: %s)",
						i, got[i].Verified, tt.want[i].Verified, string(got[i].Raw))
				}

				if tt.wantVerificationErr && got[i].VerificationError() == nil {
					t.Errorf("DockerSwarmUnlock.FromData() result %d: expected verification error", i)
				}
			}
		})
	}
}

var cmpopts = []cmp.Option{
	cmp.FilterPath(func(p cmp.Path) bool {
		return p.String() == "Raw" || p.String() == "RawV2" ||
			p.String() == "verificationError" || p.String() == "ExtraData" ||
			p.String() == "primarySecret" || p.String() == "AnalysisInfo"
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
