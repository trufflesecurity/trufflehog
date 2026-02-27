//go:build detectors
// +build detectors

package duo

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

func TestDuo_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors-duo")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	host := testSecrets.MustGetField("DUO_APIHOST")
	ikey := testSecrets.MustGetField("DUO_AUTH_IKEY")
	skey := testSecrets.MustGetField("DUO_AUTH_SKEY")
	inactiveSKey := "CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe"

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
					"Using DUO_APIHOST=%s DUO_IKEY=%s DUO_SKEY=%s",
					host, ikey, skey,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Duo,
					Verified:     true,
					Raw:          []byte(ikey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", host, ikey, skey)),
				},
			},
		},
		{
			name: "found, real secrets, verification error due to timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx: context.Background(),
				data: fmt.Appendf(
					[]byte{},
					"DUO_APIHOST=%s DUO_IKEY=%s DUO_SKEY=%s",
					host, ikey, skey,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Duo,
					Verified:     false,
					Raw:          []byte(ikey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", host, ikey, skey)),
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, real secrets, verification error due to unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "{}")},
			args: args{
				ctx: context.Background(),
				data: fmt.Appendf(
					[]byte{},
					"DUO_APIHOST=%s DUO_IKEY=%s DUO_SKEY=%s",
					host, ikey, skey,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Duo,
					Verified:     false,
					Raw:          []byte(ikey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", host, ikey, skey)),
				},
			},
			wantVerificationErr: true,
		},
		{
			name: "found, unverified (inactive secret)",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: fmt.Appendf(
					[]byte{},
					"DUO_APIHOST=%s DUO_IKEY=%s DUO_SKEY=%s",
					host, ikey, inactiveSKey,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Duo,
					Verified:     false,
					Raw:          []byte(ikey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", host, ikey, inactiveSKey)),
				},
			},
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("no duo credentials here"),
				verify: true,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Duo.FromData() error = %v, wantErr %v", err, tt.wantErr)
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf(
						"wantVerificationError=%v, verificationError=%v",
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
				t.Errorf("Duo.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestDuo_FromChunk_AdminAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors-duo")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	// Auth API credentials
	host := testSecrets.MustGetField("DUO_APIHOST")
	inactiveSKey := "CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe"

	// Admin API credentials
	adminIKey := testSecrets.MustGetField("DUO_ADMIN_IKEY")
	adminSKey := testSecrets.MustGetField("DUO_ADMIN_SKEY")

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
			name: "admin key, verified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: fmt.Appendf(
					[]byte{},
					"Using DUO_APIHOST=%s DUO_IKEY=%s DUO_SKEY=%s",
					host, adminIKey, adminSKey,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Duo,
					Verified:     true,
					Raw:          []byte(adminIKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", host, adminIKey, adminSKey)),
					ExtraData: map[string]string{
						"application": "Admin API",
					},
				},
			},
		},
		{
			name: "admin key, unverified (invalid secret)",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: fmt.Appendf(
					[]byte{},
					"Using DUO_APIHOST=%s DUO_IKEY=%s DUO_SKEY=%s",
					host, adminIKey, inactiveSKey,
				),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Duo,
					Verified:     false,
					Raw:          []byte(adminIKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", host, adminIKey, inactiveSKey)),
					ExtraData: map[string]string{
						"application": "Auth API", // Admin API credentials can sometimes be valid for Auth API, so we check Auth API if Admin API verification fails
					},
				},
			},
			wantVerificationErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Duo.FromData() error = %v, wantErr %v", err, tt.wantErr)
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf(
						"wantVerificationError=%v, verificationError=%v",
						tt.wantVerificationErr,
						got[i].VerificationError(),
					)
				}
			}

			ignoreOpts := cmpopts.IgnoreFields(
				detectors.Result{},
				"verificationError",
				"primarySecret",
			)

			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Duo.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
