package stripewebhook

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	detector_typepb "github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestStripeWebhook_Pattern(t *testing.T) {
	d := Scanner{}
	ctx := context.Background()

	// Note: test values use clearly fake/invalid secrets for pattern testing only.
	// Integration tests with real credentials should use Google Secret Manager.
	tests := []struct {
		name  string
		input string
		want  []detectors.Result
	}{
		{
			name:  "valid 32-char pattern",
			input: "STRIPE_WEBHOOK_SECRET=whsec_" + "A2345678901234567890123456789012",
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_StripeWebhook,
					Verified:     false,
				},
			},
		},
		{
			name:  "valid 64-char pattern",
			input: "webhook_secret: whsec_" + "A2345678901234567890123456789012" + "B2345678901234567890123456789012",
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_StripeWebhook,
					Verified:     false,
				},
			},
		},
		{
			name:  "no match - too short",
			input: "whsec_tooshort",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.FromData(ctx, false, []byte(tt.input))
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got,
				cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "StructuredData"),
				cmpopts.IgnoreUnexported(detectors.Result{}),
			); diff != "" {
				t.Errorf("FromData() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
