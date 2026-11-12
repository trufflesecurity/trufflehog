package firecrawl

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const (
	sampleKey  = "fc-be0ca4cc316f4f2fb73eff4971c42f99"
	sampleKey2 = "fc-0f1e2d3c4b5a69788796a5b4c3d2e1f0"
)

func TestFirecrawl_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical assignment",
			input: `FIRECRAWL_API_KEY="` + sampleKey + `"`,
			want:  []string{sampleKey},
		},
		{
			name:  "python sdk",
			input: `app = FirecrawlApp(api_key="` + sampleKey + `")`,
			want:  []string{sampleKey},
		},
		{
			name:  "bearer header",
			input: "Authorization: Bearer " + sampleKey,
			want:  []string{sampleKey},
		},
		{
			name: "finds all matches",
			input: `
				FIRECRAWL_API_KEY=` + sampleKey + `
				FIRECRAWL_API_KEY_2=` + sampleKey2 + `
			`,
			want: []string{sampleKey, sampleKey2},
		},
		{
			name:  "deduplicates repeated key",
			input: sampleKey + " " + sampleKey,
			want:  []string{sampleKey},
		},
		{
			name:  "placeholder",
			input: `FIRECRAWL_API_KEY="fc-YOUR_API_KEY"`,
			want:  []string{},
		},
		{
			name:  "too short",
			input: `FIRECRAWL_API_KEY="fc-be0ca4cc316f4f2fb73eff4971c42f9"`,
			want:  []string{},
		},
		{
			name:  "too long",
			input: `FIRECRAWL_API_KEY="fc-be0ca4cc316f4f2fb73eff4971c42f990"`,
			want:  []string{},
		},
		{
			name:  "uppercase hex is not a generated key",
			input: `FIRECRAWL_API_KEY="fc-BE0CA4CC316F4F2FB73EFF4971C42F99"`,
			want:  []string{},
		},
		{
			name:  "dashed uuid after prefix",
			input: `FIRECRAWL_API_KEY="fc-be0ca4cc-316f-4f2f-b73e-ff4971c42f99"`,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}
			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func TestFirecrawl_Verify(t *testing.T) {
	tests := []struct {
		name                string
		s                   Scanner
		wantVerified        bool
		wantVerificationErr bool
		wantExtra           map[string]string
	}{
		{
			name: "verified",
			s: Scanner{client: common.ConstantResponseHttpClient(200, `{
				"success": true,
				"data": {
					"remainingCredits": 1000,
					"planCredits": 500000,
					"billingPeriodStart": "2025-01-01T00:00:00Z",
					"billingPeriodEnd": "2025-01-31T23:59:59Z"
				}
			}`)},
			wantVerified: true,
			wantExtra: map[string]string{
				"remaining_credits": "1000",
				"plan_credits":      "500000",
			},
		},
		{
			name:         "verified with unexpected body",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `not json`)},
			wantVerified: true,
		},
		{
			name:         "invalid key",
			s:            Scanner{client: common.ConstantResponseHttpClient(401, `{"success":false,"error":"Unauthorized: Invalid token"}`)},
			wantVerified: false,
		},
		{
			name:                "rate limited is indeterminate",
			s:                   Scanner{client: common.ConstantResponseHttpClient(429, `{"success":false,"error":"Rate limit exceeded"}`)},
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "server error is indeterminate",
			s:                   Scanner{client: common.ConstantResponseHttpClient(500, `{"success":false,"error":"Internal server error"}`)},
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "timeout",
			s:                   Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			wantVerified:        false,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := test.s.FromData(context.Background(), true, []byte("FIRECRAWL_API_KEY="+sampleKey))
			require.NoError(t, err)
			require.Len(t, results, 1)

			got := results[0]
			require.Equal(t, detector_typepb.DetectorType_Firecrawl, got.DetectorType)
			require.Equal(t, "Firecrawl", got.DetectorType.String())
			require.Equal(t, sampleKey, string(got.Raw))
			require.Equal(t, map[string]string{"key": sampleKey}, got.SecretParts)
			require.Equal(t, test.wantVerified, got.Verified)
			if test.wantVerificationErr {
				require.Error(t, got.VerificationError())
			} else {
				require.NoError(t, got.VerificationError())
			}
			if diff := cmp.Diff(test.wantExtra, got.ExtraData); diff != "" {
				t.Errorf("%s ExtraData diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

// Hits Firecrawl's real credit-usage endpoint with a key that matches the
// pattern but is not a credential. Confirms 401 is determinate-invalid, not a
// false verified.
func TestFirecrawl_LiveInvalidKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Firecrawl API call")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := Scanner{}.FromData(ctx, true, []byte("FIRECRAWL_API_KEY="+sampleKey))
	require.NoError(t, err)
	require.Len(t, results, 1)

	got := results[0]
	require.Equal(t, sampleKey, string(got.Raw))
	if verr := got.VerificationError(); verr != nil {
		t.Skipf("Firecrawl credit-usage endpoint not reachable: %v", verr)
	}
	require.False(t, got.Verified, "a made-up fc- key must not verify")
}
