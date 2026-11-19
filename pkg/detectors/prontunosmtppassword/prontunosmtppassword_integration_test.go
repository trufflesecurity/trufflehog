//go:build detectors
// +build detectors

package prontunosmtppassword

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

func TestProntunoSmtpPassword_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	// A live SMTP credential: its pno_smtp_ username and pno_sp_ password.
	username := testSecrets.MustGetField("PRONTUNO_SMTP_USERNAME")
	password := testSecrets.MustGetField("PRONTUNO_SMTP_PASSWORD")
	// A password that no longer works for that username, such as the one
	// replaced by a password reset. It must still carry a valid checksum.
	inactivePassword := testSecrets.MustGetField("PRONTUNO_SMTP_PASSWORD_INACTIVE")

	expiredCtx, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

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
				data:   []byte(fmt.Sprintf("You can find a prontuno smtp login %s with password %s within", username, password)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_ProntunoSmtpPassword,
					Verified:     true,
				},
			},
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a prontuno smtp login %s with password %s within but not valid", username, inactivePassword)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_ProntunoSmtpPassword,
					Verified:     false,
				},
			},
		},
		{
			name: "found without a username, not verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a prontuno smtp password %s within", password)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_ProntunoSmtpPassword,
					Verified:     false,
				},
			},
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want: nil,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{},
			args: args{
				ctx:    expiredCtx,
				data:   []byte(fmt.Sprintf("You can find a prontuno smtp login %s with password %s within", username, password)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_ProntunoSmtpPassword,
					Verified:     false,
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, would be verified if not for an unreachable server",
			// Port 1 on localhost refuses connections.
			s: Scanner{addr: "127.0.0.1:1"},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a prontuno smtp login %s with password %s within", username, password)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_ProntunoSmtpPassword,
					Verified:     false,
				},
			},
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProntunoSmtpPassword.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Errorf("ProntunoSmtpPassword.FromData() error = %v, wantVerificationErr %v", got[i].VerificationError(), tt.wantVerificationErr)
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError", "SecretParts")
			ignoreUnexported := cmpopts.IgnoreUnexported(detectors.Result{})
			if diff := cmp.Diff(got, tt.want, ignoreOpts, ignoreUnexported); diff != "" {
				t.Errorf("ProntunoSmtpPassword.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
