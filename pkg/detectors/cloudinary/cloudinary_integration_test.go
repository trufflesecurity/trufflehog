//go:build detectors
// +build detectors

package cloudinary

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

func TestCloudinary_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	cloudName := testSecrets.MustGetField("CLOUDINARY_CLOUD_NAME")
	apiKey := testSecrets.MustGetField("CLOUDINARY_API_KEY")
	apiSecret := testSecrets.MustGetField("CLOUDINARY_SECRET_KEY")
	inactiveSecret := testSecrets.MustGetField("CLOUDINARY_INACTIVE_SECRET_KEY")

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
				data:   fmt.Appendf([]byte{}, "You can find a Cloudinary apiSecret %s, Cloudinary apiKey %v and Cloudinary cloudName %v", apiSecret, apiKey, cloudName),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Cloudinary,
					Verified:     true,
					Raw:          []byte(apiKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", cloudName, apiKey, apiSecret)),
				},
			},
			wantErr: false,
		},
		{
			name: "found, real secrets, verification error due to timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "You can find a Cloudinary apiSecret %s, Cloudinary apiKey %v and Cloudinary cloudName %v", apiSecret, apiKey, cloudName),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Cloudinary,
					Verified:     false,
					Raw:          []byte(apiKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", cloudName, apiKey, apiSecret)),
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, real secrets, verification error due to unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "{}")},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "You can find a Cloudinary apiSecret %s, Cloudinary apiKey %v and Cloudinary cloudName %v", apiSecret, apiKey, cloudName),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Cloudinary,
					Verified:     false,
					Raw:          []byte(apiKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", cloudName, apiKey, apiSecret)),
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   fmt.Appendf([]byte{}, "You can find a Cloudinary inactiveapiSecret %s, Cloudinary apiKey %v and Cloudinary cloudName %v", inactiveSecret, apiKey, cloudName),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Cloudinary,
					Verified:     false,
					Raw:          []byte(apiKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", cloudName, apiKey, inactiveSecret)),
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
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
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Cloudinary.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "ExtraData", "verificationError", "primarySecret")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Cloudinary.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
