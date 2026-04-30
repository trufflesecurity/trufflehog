//go:build detectors
// +build detectors

package microsoftteamswebhook

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

func TestScanner_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("MICROSOFT_TEAMS_WEBHOOK_V2")
	inactiveSecret := testSecrets.MustGetField("MICROSOFT_TEAMS_WEBHOOK_V2_INACTIVE")

	tests := []struct {
		name                string
		s                   Scanner
		data                []byte
		verify              bool
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name:   "found, verified",
			s:      Scanner{},
			data:   []byte(fmt.Sprintf("teams webhook %s", secret)),
			verify: true,
			want: []detectors.Result{
				{DetectorType: detector_typepb.DetectorType_MicrosoftTeamsWebhook, Verified: true},
			},
		},
		{
			name:   "found, unverified (inactive secret)",
			s:      Scanner{},
			data:   []byte(fmt.Sprintf("teams webhook %s", inactiveSecret)),
			verify: true,
			want: []detectors.Result{
				{DetectorType: detector_typepb.DetectorType_MicrosoftTeamsWebhook, Verified: false},
			},
		},
		{
			name:                "found, verification error (unexpected response)",
			s:                   Scanner{client: common.ConstantResponseHttpClient(500, "")},
			data:                []byte(fmt.Sprintf("teams webhook %s", secret)),
			verify:              true,
			want:                []detectors.Result{{DetectorType: detector_typepb.DetectorType_MicrosoftTeamsWebhook, Verified: false}},
			wantVerificationErr: true,
		},
		{
			name:                "found, verification error (timeout)",
			s:                   Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			data:                []byte(fmt.Sprintf("teams webhook %s", secret)),
			verify:              true,
			want:                []detectors.Result{{DetectorType: detector_typepb.DetectorType_MicrosoftTeamsWebhook, Verified: false}},
			wantVerificationErr: true,
		},
		{
			name:   "not found",
			s:      Scanner{},
			data:   []byte("no secret here"),
			verify: true,
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(context.Background(), tt.verify, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromData() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: %+v", got[i])
				}
				if len(got[i].SecretParts) == 0 {
					t.Fatalf("no secret parts present: %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Errorf("verificationError = %v, wantVerificationErr %v",
						got[i].VerificationError(), tt.wantVerificationErr)
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "ExtraData", "verificationError", "primarySecret", "SecretParts")
			if diff := cmp.Diff(tt.want, got, ignoreOpts); diff != "" {
				t.Errorf("FromData() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkFromData(b *testing.B) {
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
