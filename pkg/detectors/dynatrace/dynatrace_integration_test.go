//go:build detectors

package dynatrace

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

func TestDynatrace_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "dynatrace")
	if err != nil {
		t.Skipf("Dynatrace integration secrets not configured, skipping: %s", err)
	}
	token := testSecrets.MustGetField("DYNATRACE_TOKEN")
	tenant := testSecrets.MustGetField("DYNATRACE_TENANT")
	inactiveToken := testSecrets.MustGetField("DYNATRACE_INACTIVE")

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
				ctx:    ctx,
				data:   []byte(fmt.Sprintf("tenant %s token %s", tenant, token)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Dynatrace,
					Verified:     true,
				},
			},
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    ctx,
				data:   []byte(fmt.Sprintf("tenant %s token %s", tenant, inactiveToken)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Dynatrace,
					Verified:     false,
				},
			},
		},
		{
			name: "found, no tenant in chunk, not verified",
			s:    Scanner{},
			args: args{
				ctx:    ctx,
				data:   []byte(fmt.Sprintf("just a token %s with no tenant", token)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Dynatrace,
					Verified:     false,
				},
			},
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    ctx,
				data:   []byte("no dynatrace token here"),
				verify: true,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Dynatrace.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
			ignoreOpts := cmp.Options{
				cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "Redacted", "ExtraData", "SecretParts"),
				cmpopts.IgnoreUnexported(detectors.Result{}),
			}
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Dynatrace.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}
