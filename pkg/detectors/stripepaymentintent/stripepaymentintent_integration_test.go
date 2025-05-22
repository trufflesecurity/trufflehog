//go:build detectors
// +build detectors

package stripepaymentintent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestStripepaymentintent_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("STRIPE_SECRET")
	paymentIntent := testSecrets.MustGetField("STRIPE_PAYMENT_INTENT")
	secretInactive := testSecrets.MustGetField("STRIPE_INACTIVE")
	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		wantVerified        bool // Instead of expecting exact results, check if any result is verified
		wantResultCount     int  // Expected number of results
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a stripepaymentintent secret %s and payment intent: %s within", secret, paymentIntent)),
				verify: true,
			},
			wantVerified:        true, // At least one result should be verified
			wantResultCount:     1,    // 1 client secret × 1 key = 1 result
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a stripepaymentintent secret %s and payment intent %s within but not valid", secretInactive, paymentIntent)),
				verify: true,
			},
			wantVerified:        false, // No results should be verified
			wantResultCount:     1,     // 1 client secret × 1 key = 1 result
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
			wantVerified:        false,
			wantResultCount:     0, // No results expected
			wantErr:             false,
			wantVerificationErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Stripepaymentintent.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check result count
			if len(got) != tt.wantResultCount {
				t.Errorf("Stripepaymentintent.FromData() got %d results, want %d", len(got), tt.wantResultCount)
				return
			}

			// Check each result
			hasVerified := false
			for i := range got {
				// Check that all results have the correct detector type
				if got[i].DetectorType != detectorspb.DetectorType_StripePaymentIntent {
					t.Errorf("Stripepaymentintent.FromData() result %d has wrong DetectorType", i)
				}

				// Check that raw secret is present
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present in result %d: \n %+v", i, got[i])
				}

				// Check that RawV2 is present (should contain client secret + key)
				if len(got[i].RawV2) == 0 {
					t.Fatalf("no rawV2 present in result %d: \n %+v", i, got[i])
				}

				// Check verification error expectation
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}

				// Track if any result is verified
				if got[i].Verified {
					hasVerified = true
				}
			}

			// Check verification expectation
			if hasVerified != tt.wantVerified {
				t.Errorf("Stripepaymentintent.FromData() hasVerified = %v, want %v", hasVerified, tt.wantVerified)
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
