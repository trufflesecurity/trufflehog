//go:build detectors
// +build detectors

package salesforceoauth2

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

func TestSalesforceOauth2_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Fetch the correct secrets needed for the OAuth2 Client Credentials flow.
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	domain := testSecrets.MustGetField("SALESFORCE_OAUTH2_DOMAIN")
	consumerKey := testSecrets.MustGetField("SALESFORCE_OAUTH2_CONSUMER_KEY")
	consumerSecret := testSecrets.MustGetField("SALESFORCE_OAUTH2_CONSUMER_SECRET")
	inactiveSecret := testSecrets.MustGetField("SALESFORCE_OAUTH2_INACTIVE_CONSUMER_SECRET")

	type args struct {
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
			name: "found one valid trio, verified",
			s:    Scanner{},
			args: args{
				data:   []byte(fmt.Sprintf("domain: %s, key: %s, secret: %s", domain, consumerKey, consumerSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SalesforceOauth2,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found one invalid trio, unverified",
			s:    Scanner{},
			args: args{
				data:   []byte(fmt.Sprintf("domain: %s, key: %s, secret: %s", domain, consumerKey, inactiveSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SalesforceOauth2,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false, // An invalid secret is a clean "no", not an error.
		},
		{
			name: "multiple findings, one verified",
			s:    Scanner{},
			args: args{
				data:   []byte(fmt.Sprintf("domain: %s, key: %s, valid_secret: %s, invalid_secret: %s", domain, consumerKey, consumerSecret, inactiveSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SalesforceOauth2,
					Verified:     true, // The valid secret combination
				},
				{
					DetectorType: detectorspb.DetectorType_SalesforceOauth2,
					Verified:     false, // The invalid secret combination
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found (missing a component)",
			s:    Scanner{},
			args: args{
				data:   []byte(fmt.Sprintf("key: %s, secret: %s", consumerKey, consumerSecret)), // No domain
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				data:   []byte(fmt.Sprintf("domain: %s, key: %s, secret: %s", domain, consumerKey, consumerSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SalesforceOauth2,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, unexpected api response",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				data:   []byte(fmt.Sprintf("domain: %s, key: %s, secret: %s", domain, consumerKey, consumerSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SalesforceOauth2,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(context.Background(), tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Since the order of results can vary with maps, we use a more robust comparison.
			// This checks that for every `want` result, there is a matching `got` result.
			opts := []cmp.Option{
				cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError", "ExtraData", "VerificationFromCache", "primarySecret"),
				cmpopts.SortSlices(func(a, b detectors.Result) bool { return a.Verified }),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("FromData() results mismatch (-want +got):\n%s", diff)
			}

			// Also check that verification errors match expectations across all results.
			var gotErr bool
			for _, r := range got {
				if r.VerificationError() != nil {
					gotErr = true
					break
				}
			}
			if gotErr != tt.wantVerificationErr {
				t.Errorf("wantVerificationErr = %v, but got an error state of %v", tt.wantVerificationErr, gotErr)
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
