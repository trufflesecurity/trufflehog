//go:build detectors
// +build detectors

package robinhoodcrypto

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

func TestRobinhoodcrypto_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	// Valid and active credentials.
	apiKey := testSecrets.MustGetField("ROBINHOODCRYPTO_APIKEY")
	privateKey := testSecrets.MustGetField("ROBINHOODCRYPTO_PRIVATEKEY")

	// Valid but inactive credentials.
	inactiveApiKey := testSecrets.MustGetField("ROBINHOODCRYPTO_APIKEY_INACTIVE")
	inactivePrivateKey := testSecrets.MustGetField("ROBINHOODCRYPTO_PRIVATEKEY_INACTIVE")

	// Invalid credentials.
	deletedApiKey := testSecrets.MustGetField("ROBINHOODCRYPTO_APIKEY_DELETED")
	deletedPrivateKey := testSecrets.MustGetField("ROBINHOODCRYPTO_PRIVATEKEY_DELETED")

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
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", apiKey, privateKey,
				)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, verified, but inactive",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", inactiveApiKey,
					inactivePrivateKey,
				)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", deletedApiKey,
					deletedPrivateKey,
				)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", apiKey, privateKey,
				)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", apiKey, privateKey,
				)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
				if (err != nil) != tt.wantErr {
					t.Errorf("Robinhoodcrypto.FromData() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				for i := range got {
					if len(got[i].Raw) == 0 {
						t.Fatalf("no raw secret present: \n %+v", got[i])
					}
					if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
						t.Fatalf(
							"wantVerificationError = %v, verification error = %v", tt.wantVerificationErr,
							got[i].VerificationError(),
						)
					}
				}
				ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "ExtraData", "Raw", "RawV2", "verificationError")
				if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
					t.Errorf("Robinhoodcrypto.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
				}
			},
		)
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(
			name, func(b *testing.B) {
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					_, err := s.FromData(ctx, false, data)
					if err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}
