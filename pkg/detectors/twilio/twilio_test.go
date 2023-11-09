//go:build detectors
// +build detectors

package twilio

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

func TestTwilio_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("TWILLIO_API")
	secretInactive := testSecrets.MustGetField("TWILLIO_API_INACTIVE")
	id := testSecrets.MustGetField("TWILLIO_ID")

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
				data:   []byte(fmt.Sprintf("You can find a twillio secret %s within awsId %s", secret, id)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Twilio,
					Verified:     true,
					Redacted:     id,
					RawV2:        []byte(id + secret),
				},
			},
			wantErr: false,
		},
		{
			name: "found, not verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a twillio secret %s within awsId %s", secretInactive, id)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Twilio,
					Verified:     false,
					Redacted:     id,
					RawV2:        []byte(id + secretInactive),
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
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(100 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a twillio secret %s within awsId %s", secret, id)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Twilio,
					Verified:     false,
					Redacted:     id,
					RawV2:        []byte(id + secret),
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a twillio secret %s within awsId %s", secret, id)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Twilio,
					Verified:     false,
					Redacted:     id,
					RawV2:        []byte(id + secret),
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Twilio.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Twilio.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
