//go:build detectors

package nuntiq

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

func TestNuntiq_FromChunk(t *testing.T) {
	filename := os.Getenv("TEST_SECRET_FILE")
	if filename == "" {
		t.Skip("set TEST_SECRET_FILE with NUNTIQ and NUNTIQ_INACTIVE to run live verification")
	}
	secrets, err := common.GetSecretFromEnv(filename)
	if err != nil {
		t.Fatal("could not load Nuntiq test credentials")
	}
	for _, tt := range []struct {
		field    string
		verified bool
	}{
		{field: "NUNTIQ", verified: true},
		{field: "NUNTIQ_INACTIVE", verified: false},
	} {
		t.Run(tt.field, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s := Scanner{}
			results, err := s.FromData(ctx, true, []byte("NUNTIQ_API_KEY="+secrets.MustGetField(tt.field)))
			if err != nil || len(results) != 1 {
				t.Fatal("expected one Nuntiq credential")
			}
			if results[0].Verified != tt.verified || results[0].VerificationError() != nil {
				t.Fatalf("unexpected verification result: verified=%v, error=%v", results[0].Verified, results[0].VerificationError())
			}
		})
	}
}
