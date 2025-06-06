//go:build detectors
// +build detectors

package launchdarkly

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestLaunchDarkly_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors3")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	sdkSecret := testSecrets.MustGetField("LAUNCHDARKLY_SDK_TOKEN")
	secret := testSecrets.MustGetField("LAUNCHDARKLY_TOKEN")
	inactiveSecret := testSecrets.MustGetField("LAUNCHDARKLY_INACTIVE")

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
				data:   []byte(fmt.Sprintf("You can find a launchdarkly secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LaunchDarkly,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a launchdarkly secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LaunchDarkly,
					Verified:     false,
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
			name: "found, valid but unexpected api response",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a launchdarkly secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LaunchDarkly,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, valid sdk token",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a launchdarkly sdk secret %s within", sdkSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LaunchDarkly,
					Verified:     true,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("LaunchDarkly.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
				got[i].AnalysisInfo = nil

				// Do we expect to be comparing the ExtraData?
				got[i].ExtraData = nil

				// If we expect a verification error, copy over the one we got so the later comparison can work
				if tt.wantVerificationErr && len(tt.want) > i {
					tt.want[i].SetVerificationError(got[i].VerificationError())
				}
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("LaunchDarkly.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
