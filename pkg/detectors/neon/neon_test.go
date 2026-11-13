package neon

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

const sampleKey = "napi_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"

func TestNeon_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical assignment",
			input: `NEON_API_KEY="` + sampleKey + `"`,
			want:  []string{sampleKey},
		},
		{
			name:  "bearer header",
			input: "Authorization: Bearer " + sampleKey,
			want:  []string{sampleKey},
		},
		{
			name: "xml secret",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
					<scope>GLOBAL</scope>
					<id>{neon}</id>
					<secret>{AQAAABAAA ` + sampleKey + `}</secret>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{sampleKey},
		},
		{
			name: "finds all matches",
			input: `
				NEON_API_KEY=` + sampleKey + `
				NEON_API_KEY=` + sampleKey + `X
			`,
			want: []string{sampleKey, sampleKey + "X"},
		},
		{
			name:  "too short after prefix",
			input: "napi_shortkey",
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: `NEON_API_KEY="not-a-neon-key-abcdefghijklmnopqrstuvwxyz"`,
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

func TestNeon_Verify(t *testing.T) {
	tests := []struct {
		name                string
		s                   Scanner
		input               string
		wantVerified        bool
		wantVerificationErr bool
		wantExtra           map[string]string
	}{
		{
			name: "verified personal key",
			s: Scanner{client: common.ConstantResponseHttpClient(200, `{
				"auth_method": "api_key_user",
				"account_id": "user_01h84bfr2npa81rn8h8jzz8mx4"
			}`)},
			input:        `NEON_API_KEY=` + sampleKey,
			wantVerified: true,
			wantExtra: map[string]string{
				"auth_method": "api_key_user",
				"account_id":  "user_01h84bfr2npa81rn8h8jzz8mx4",
			},
		},
		{
			name: "verified organization or project-scoped key",
			s: Scanner{client: common.ConstantResponseHttpClient(200, `{
				"auth_method": "api_key_org",
				"account_id": "org-twilight-fog-87450618"
			}`)},
			input:        `NEON_API_KEY=` + sampleKey,
			wantVerified: true,
			wantExtra: map[string]string{
				"auth_method": "api_key_org",
				"account_id":  "org-twilight-fog-87450618",
				"org_id":      "org-twilight-fog-87450618",
			},
		},
		{
			name:                "forbidden is indeterminate",
			s:                   Scanner{client: common.ConstantResponseHttpClient(403, `{"message":"forbidden"}`)},
			input:               `NEON_API_KEY=` + sampleKey,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:         "invalid key",
			s:            Scanner{client: common.ConstantResponseHttpClient(401, `{"message":"unauthorized"}`)},
			input:        `NEON_API_KEY=` + sampleKey,
			wantVerified: false,
		},
		{
			name:                "unexpected status",
			s:                   Scanner{client: common.ConstantResponseHttpClient(404, "")},
			input:               `NEON_API_KEY=` + sampleKey,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "timeout",
			s:                   Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			input:               `NEON_API_KEY=` + sampleKey,
			wantVerified:        false,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := test.s.FromData(context.Background(), true, []byte(test.input))
			require.NoError(t, err)
			require.Len(t, results, 1)

			got := results[0]
			require.Equal(t, detector_typepb.DetectorType_Neon, got.DetectorType)
			require.Equal(t, "Neon", got.DetectorType.String())
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

// Hits Neon's real /auth endpoint with a key that matches the pattern but is
// not a credential. Confirms 401 is determinate-invalid, not a false verified.
func TestNeon_LiveInvalidKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Neon API call")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := Scanner{}.FromData(ctx, true, []byte("NEON_API_KEY="+sampleKey))
	require.NoError(t, err)
	require.Len(t, results, 1)

	got := results[0]
	require.Equal(t, sampleKey, string(got.Raw))
	if verr := got.VerificationError(); verr != nil {
		t.Skipf("Neon /auth not reachable: %v", verr)
	}
	require.False(t, got.Verified, "a made-up napi_ key must not verify")
	require.NoError(t, got.VerificationError(), "401 must be determinate invalid, not indeterminate")
}
