//go:build detectors
// +build detectors

package twilioapikey

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

func TestTwilioAPIKey_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	secret := testSecrets.MustGetField("TWILLIO_SECRET")
	secretInactive := testSecrets.MustGetField("TWILLIO_SECRET_INACTIVE")
	apiKey := testSecrets.MustGetField("TWILLIO_APIKEY")

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
				data:   []byte(fmt.Sprintf("You can find a twillio secret %s within awsId %s", secret, apiKey)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Twilio,
					Verified:     true,
					Redacted:     secret,
					RawV2:        []byte(apiKey + secret),
					ExtraData: map[string]string{
						"account_sid":   "ACa5b6165773490f33f226d71e7ffacff5",
						"friendly_name": "MyServiceName",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, not verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a twillio secret %s within awsId %s", secretInactive, apiKey)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Twilio,
					Verified:     false,
					Redacted:     secretInactive,
					RawV2:        []byte(apiKey + secretInactive),
					ExtraData:    map[string]string{},
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError", "AnalysisInfo")
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
