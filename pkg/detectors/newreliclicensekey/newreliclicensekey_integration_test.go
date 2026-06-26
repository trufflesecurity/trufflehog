//go:build integration

package newreliclicensekey

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestNewRelicLicenseKey_Integration(t *testing.T) {
	ctx := context.Background()
	s := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{s})

	tests := []struct {
		name         string
		input        string
		want         []string
		wantVerified bool
	}{
		{
			name:         "valid key from environment",
			input:        "NEW_RELIC_LICENSE_KEY=" + os.Getenv("NEWRELIC_LICENSE_KEY"),
			want:         []string{os.Getenv("NEWRELIC_LICENSE_KEY")},
			wantVerified: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if os.Getenv("NEWRELIC_LICENSE_KEY") == "" {
				t.Skip("Skipping integration test: NEWRELIC_LICENSE_KEY not set")
			}

			chunkSpecificDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(chunkSpecificDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", s.Keywords(), test.input)
				return
			}

			results, err := s.FromData(ctx, true, []byte(test.input))
			assert.NoError(t, err)
			assert.NotEmpty(t, results)

			if test.wantVerified {
				assert.Equal(t, test.wantVerified, results[0].Verified)
				t.Logf("✅ Verified: %v", results[0].Verified)
				t.Logf("✅ ExtraData: %v", results[0].ExtraData)
			}

			// Check that all expected secrets were found
			actual := make(map[string]struct{})
			for _, r := range results {
				var key string
				if len(r.RawV2) > 0 {
					key = string(r.RawV2)
				} else {
					key = string(r.Raw)
				}
				actual[key] = struct{}{}
			}

			for _, w := range test.want {
				if _, found := actual[w]; !found && !bytes.Contains([]byte(w), []byte("EXAMPLE")) {
					t.Errorf("expected secret %q not found", w)
				}
			}
		})
	}
}
