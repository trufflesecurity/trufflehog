//go:build detectors
// +build detectors

package hashicorpbatchtoken

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestBatchToken_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Fetch test secrets
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets: %s", err)
	}

	vaultURL := testSecrets.MustGetField("HASHICORPVAULT_CLOUD_URL")

	// This token has maximum TTL of 32days (768h), so it should still be valid by the time this test runs
	// but if the test fails due to an invalid token, this is the most likely culprit and the token may need to be regenerated.
	// To regenerate the token run this command in vault web cli:
	// write auth/token/create type=batch policies="test-policy" ttl="768h" no_parent=true
	batchToken := testSecrets.MustGetField("HASHICORPVAULT_BATCH_TOKEN")

	fakeToken := "hvb.fakeinvalidtokenaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		name                string
		input               string
		verify              bool
		wantTokens          []string
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:   "valid batch token with URL, verify",
			input:  fmt.Sprintf("%s\n%s", batchToken, vaultURL),
			verify: true,
			wantTokens: []string{
				batchToken + vaultURL,
			},
			wantVerified:        true,
			wantVerificationErr: false,
		},
		{
			name:   "invalid batch token with URL, verify",
			input:  fmt.Sprintf("%s\n%s", fakeToken, vaultURL),
			verify: true,
			wantTokens: []string{
				fakeToken + vaultURL,
			},
			wantVerified:        false,
			wantVerificationErr: false,
		},
		{
			name:   "valid batch token with URL, no verify",
			input:  fmt.Sprintf("%s\n%s", batchToken, vaultURL),
			verify: false,
			wantTokens: []string{
				batchToken + vaultURL,
			},
			wantVerified:        false,
			wantVerificationErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := Scanner{}
			scanner.UseFoundEndpoints(true)
			scanner.UseCloudEndpoint(true)

			results, err := scanner.FromData(ctx, tt.verify, []byte(tt.input))
			require.NoError(t, err)

			if len(results) != len(tt.wantTokens) {
				t.Fatalf("expected %d results, got %d", len(tt.wantTokens), len(results))
			}

			for i, r := range results {
				if string(r.RawV2) != tt.wantTokens[i] && string(r.Raw) != tt.wantTokens[i] {
					t.Errorf("expected token %s, got %s", tt.wantTokens[i], string(r.Raw))
				}

				if r.Verified != tt.wantVerified {
					t.Errorf("expected verified=%v, got %v", tt.wantVerified, r.Verified)
				}

				if (r.VerificationError() != nil) != tt.wantVerificationErr {
					t.Errorf("expected verification error=%v, got %v", tt.wantVerificationErr, r.VerificationError())
				}
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
