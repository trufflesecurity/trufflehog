//go:build detectors
// +build detectors

package braintrust

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

func TestBraintrust_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Load secrets from GCP (same pattern as other detectors)
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	activeToken := testSecrets.MustGetField("BRAINTRUST_API_KEY")
	inactiveToken := "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

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
				data:   fmt.Appendf([]byte{}, "Using Braintrust API key %s", activeToken),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_BrainTrustApiKey,
					Verified:     true,
					Raw:          []byte(activeToken),
					Redacted:     activeToken[:8] + "...",
				},
			},
		},
		{
			name: "found, real token, verification error due to timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "Using Braintrust API key %s", activeToken),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_BrainTrustApiKey,
					Verified:     false,
					Raw:          []byte(activeToken),
					Redacted:     activeToken[:8] + "...",
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, real token, verification error due to unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "{}")},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "Using Braintrust API key %s", activeToken),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_BrainTrustApiKey,
					Verified:     false,
					Raw:          []byte(activeToken),
					Redacted:     activeToken[:8] + "...",
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, unverified (inactive token)",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "Using Braintrust API key %s", inactiveToken),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_BrainTrustApiKey,
					Verified:     false,
					Raw:          []byte(inactiveToken),
					Redacted:     inactiveToken[:8] + "...",
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
				t.Fatalf("Braintrust.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
				t.Errorf("Braintrust.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkBraintrust_FromData(b *testing.B) {
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
