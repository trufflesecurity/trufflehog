package boxoauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	clientId            = common.GenerateRandomPassword(true, true, true, false, 32)
	clientSecret        = common.GenerateRandomPassword(true, true, true, false, 32)
	invalidClientSecret = common.GenerateRandomPassword(true, true, true, true, 32)
	subjectId           = "1234567890"
	subjectId2          = "9876543210"
)

func TestBoxOauth_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name        string
		input       string
		wantCount   int    // expected number of results
		wantRawV2   string // expected RawV2 on every result (always clientId+clientSecret)
		wantMatched bool   // whether keywords should match at all
	}{
		{
			name:        "valid pattern - no subject id",
			input:       fmt.Sprintf("box id = '%s' box secret = '%s'", clientId, clientSecret),
			wantCount:   1,
			wantRawV2:   clientId + clientSecret,
			wantMatched: true,
		},
		{
			name:        "valid pattern - with one subject id",
			input:       fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId),
			wantCount:   1,
			wantRawV2:   clientId + clientSecret,
			wantMatched: true,
		},
		{
			name:        "valid pattern - with multiple subject ids",
			input:       fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s' subject = '%s'", clientId, clientSecret, subjectId, subjectId2),
			wantCount:   2, // one result per subject id
			wantRawV2:   clientId + clientSecret,
			wantMatched: true,
		},
		{
			name:        "invalid pattern - secret contains special characters",
			input:       fmt.Sprintf("box id = '%s' box secret = '%s'", clientId, invalidClientSecret),
			wantCount:   0,
			wantMatched: false,
		},
		{
			name:        "invalid pattern - no keyword separation",
			input:       fmt.Sprintf("box = '%s|%s'", clientId, invalidClientSecret),
			wantCount:   0,
			wantMatched: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))

			if !test.wantMatched {
				results, err := d.FromData(context.Background(), false, []byte(test.input))
				require.NoError(t, err)
				assert.Empty(t, results)
				return
			}

			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			require.Lenf(t, results, test.wantCount,
				"expected %d results, got %d", test.wantCount, len(results))

			for i, r := range results {
				assert.Equalf(t, test.wantRawV2, string(r.RawV2),
					"result[%d] RawV2 mismatch", i)
			}
		})
	}
}
