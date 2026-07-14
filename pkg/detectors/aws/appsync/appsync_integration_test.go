//go:build detectors
// +build detectors

package appsync

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestAppSync_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Secrets are expected to be stored similarly to other detector tests
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	activeKey := testSecrets.MustGetField("APPSYNC_API_KEY")
	endpoint := testSecrets.MustGetField("APPSYNC_API_URL")

	revokedEndpoint := "https://nr2nchyfwvc53lgrlvsa2pfpzq.appsync-api.us-east-1.amazonaws.com/graphql"
	inactiveKey := "da2-abcdefghijklmnopqrstuvwxyz"

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
				data:   fmt.Appendf([]byte{}, "endpoint=%s key=%s", endpoint, activeKey),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_AWSAppSync,
					Verified:     true,
					Raw:          []byte(activeKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s", endpoint, activeKey)),
				},
			},
		},
		{
			name: "found, verification error due to timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "endpoint=%s key=%s", endpoint, activeKey),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_AWSAppSync,
					Verified:     false,
					Raw:          []byte(activeKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s", endpoint, activeKey)),
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, verification error unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "{}")},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "endpoint=%s key=%s", endpoint, activeKey),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_AWSAppSync,
					Verified:     false,
					Raw:          []byte(activeKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s", endpoint, activeKey)),
				},
			},
			wantVerificationErr: true,
		},
		// Host will be unreachable for such cases
		{
			name: "found, Revoked key and endpoint",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "endpoint=%s key=%s", revokedEndpoint, inactiveKey),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_AWSAppSync,
					Verified:     false,
					Raw:          []byte(inactiveKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s", revokedEndpoint, inactiveKey)),
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, valid endpoint and invalid key",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "endpoint=%s key=%s", endpoint, inactiveKey),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_AWSAppSync,
					Verified:     false,
					Raw:          []byte(inactiveKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s", endpoint, inactiveKey)),
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
				t.Fatalf("AppSync.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
				"SecretParts",
			)

			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("AppSync.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkAppSync_FromData(b *testing.B) {
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
