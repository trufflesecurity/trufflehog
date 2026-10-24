//go:build detectors
// +build detectors

package fireworks

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

func TestFireworks_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("FIREWORKS")
	inactiveSecret := testSecrets.MustGetField("FIREWORKS_INACTIVE")

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
				data:   []byte(fmt.Sprintf("You can find a fireworks secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Fireworks,
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
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a fireworks secret %s within", inactiveSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Fireworks,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Scanner.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Errorf("Scanner.FromData() verification error = %v, wantVerificationErr %v", got[i].VerificationError(), tt.wantVerificationErr)
				}
			}
			opts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "ExtraData", "SecretParts", "verificationError")
			if diff := cmp.Diff(got, tt.want, opts, cmpopts.IgnoreUnexported(detectors.Result{})); diff != "" {
				t.Errorf("Scanner.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}
