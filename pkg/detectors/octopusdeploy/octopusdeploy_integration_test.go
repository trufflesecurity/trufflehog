//go:build detectors
// +build detectors

package octopusdeploy

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

func TestOctopusDeploy_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Expect secrets structured like:
	// OCTOPUS_CLOUD_URL = acme.octopus.app
	// OCTOPUS_API_KEY = API-XXXXXXXXXXXXXXXXXXXXXXXXXXXX
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	baseURL := testSecrets.MustGetField("OCTOPUS_CLOUD_URL")
	activeToken := testSecrets.MustGetField("OCTOPUS_API_KEY")

	inactiveToken := "API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

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
				data: fmt.Appendf(
					[]byte{},
					"Server %s using key %s",
					baseURL,
					activeToken,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OctopusDeploy,
					Verified:     true,
					Raw:          []byte(activeToken),
					RawV2:        []byte(fmt.Sprintf("%s:%s", baseURL, activeToken)),
				},
			},
		},
		{
			name: "found, real token, verification timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx: context.Background(),
				data: fmt.Appendf(
					[]byte{},
					"%s %s",
					baseURL,
					activeToken,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OctopusDeploy,
					Verified:     false,
					Raw:          []byte(activeToken),
					RawV2:        []byte(fmt.Sprintf("%s:%s", baseURL, activeToken)),
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, real token, unexpected api response",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "{}")},
			args: args{
				ctx: context.Background(),
				data: fmt.Appendf(
					[]byte{},
					"%s %s",
					baseURL,
					activeToken,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OctopusDeploy,
					Verified:     false,
					Raw:          []byte(activeToken),
					RawV2:        []byte(fmt.Sprintf("%s:%s", baseURL, activeToken)),
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, unverified (inactive token)",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: fmt.Appendf(
					[]byte{},
					"%s %s",
					baseURL,
					inactiveToken,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OctopusDeploy,
					Verified:     false,
					Raw:          []byte(inactiveToken),
					RawV2:        []byte(fmt.Sprintf("%s:%s", baseURL, inactiveToken)),
				},
			},
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("no secrets here"),
				verify: true,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("OctopusDeploy.FromData() error = %v, wantErr %v", err, tt.wantErr)
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf(
						"wantVerificationError = %v, verification error = %v",
						tt.wantVerificationErr,
						got[i].VerificationError(),
					)
				}
			}

			ignoreOpts := cmpopts.IgnoreFields(
				detectors.Result{},
				"ExtraData",
				"verificationError",
				"primarySecret",
			)

			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("OctopusDeploy.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkOctopusDeploy_FromData(b *testing.B) {
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
