//go:build detectors
// +build detectors

package slack

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

func TestSlack_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("SLACK")
	secretInactive := testSecrets.MustGetField("SLACK_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}

	tests := []struct {
		name                string
		s                   Scanner
		args                args
		wantResults         []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified",
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a slack secret %s within", secret)),
				verify: true,
			},
			wantResults: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Slack,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found but unverified",
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a slack secret %s within", secretInactive)),
				verify: true,
			},
			wantResults: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Slack,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a slack secret %s within", secret)),
				verify: true,
			},
			wantResults: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Slack,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "unexpected auth response",
			s:    Scanner{client: common.ConstantResponseHttpClient(200, `{"ok": false, "error": "unexpected_error"}`)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a slack secret %s within", secret)),
				verify: true,
			},
			wantResults: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Slack,
					Verified:     false,
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
				t.Errorf("Slack.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil

				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError")
			if diff := cmp.Diff(got, tt.wantResults, ignoreOpts); diff != "" {
				t.Errorf("Slack.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
