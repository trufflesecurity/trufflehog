//go:build detectors
// +build detectors

package spectralops

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestSpectralOps_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Secrets are expected to be stored similarly to other detector tests
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	activeToken := testSecrets.MustGetField("SPECTRALOPS_PERSONAL_TOKEN")
	inactiveToken := "spu-3f10194ca38240ddb880bab79492384b"

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
				data:   fmt.Appendf([]byte{}, "Using Spectral API token %s for scan", activeToken),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SpectralOps,
					Verified:     true,
					Raw:          []byte(activeToken),
					RawV2:        []byte(activeToken),
				},
			},
		},
		{
			name: "found, real token, verification error due to timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "Using Spectral API token %s for scan", activeToken),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SpectralOps,
					Verified:     false,
					Raw:          []byte(activeToken),
					RawV2:        []byte(activeToken),
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, real token, verification error due to unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "{}")},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "Using Spectral API token %s for scan", activeToken),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SpectralOps,
					Verified:     false,
					Raw:          []byte(activeToken),
					RawV2:        []byte(activeToken),
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, unverified (inactive token)",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "Using Spectral API token %s for scan", inactiveToken),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SpectralOps,
					Verified:     false,
					Raw:          []byte(inactiveToken),
					RawV2:        []byte(inactiveToken),
				},
			},
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("no secrets here"),
				verify: true,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SpectralOps.FromData() error = %v, wantErr %v", err, tt.wantErr)
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf(
						"wantVerificationError = %v, verification error = %v",
						tt.wantVerificationErr,
						got[i].VerificationError(),
					)
				}
			}

			ignoreOpts := cmpopts.IgnoreFields(
				detectors.Result{},
				"ExtraData",
				"verificationError",
				"primarySecret",
			)

			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("SpectralOps.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkSpectralOps_FromData(b *testing.B) {
	ctx := context.Background()
	s := Scanner{}

	for name, data := range detectors.MustGetBenchmarkData() {
		b.Run(name, func(b *testing.B) {
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
