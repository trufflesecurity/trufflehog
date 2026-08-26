package deepl

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestDeepl_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	proKey := "df4385c2-33de-e423-4134-ca1f7b3ea8b7"
	freeKey := "279a2e9d-83b3-c416-7e2d-f721593e42a0:fx"
	adminKey := "a1b2c3d4-e5f6-7890-abcd-ef1234567890:adm"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "pro key near deepl identifier",
			input: `deepl_api_key = "` + proKey + `"`,
			want:  []string{proKey},
		},
		{
			name:  "free key with :fx suffix",
			input: "Authorization: DeepL-Auth-Key " + freeKey,
			want:  []string{freeKey},
		},
		{
			name:  "admin key with :adm suffix",
			input: "DEEPL_ADMIN_KEY=" + adminKey,
			want:  []string{adminKey},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
					<scope>GLOBAL</scope>
					<id>{deepl}</id>
					<secret>{AQAAABAAA ` + proKey + `}</secret>
					<description>configuration for production</description>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{proKey},
		},
		{
			name: "finds all matches",
			input: `
				deepl_pro = ` + proKey + `
				deepl_free = ` + freeKey + `
			`,
			want: []string{proKey, freeKey},
		},
		{
			name:  "does not report unsuffixed uuid when :fx form is present",
			input: "DeepL-Auth-Key " + freeKey,
			want:  []string{freeKey},
		},
		{
			name: "plain uuid far from deepl is ignored",
			input: "deepl credentials live in the secrets manager" + strings.Repeat(".", 80) + `
				unrelated_uuid = ` + proKey,
			want: nil,
		},
		{
			name:  "known false positive uuid is ignored",
			input: `deepl_api_key = "00000000-0000-0000-0000-000000000000"`,
			want:  nil,
		},
		{
			name:  "invalid pattern",
			input: `deepl_api_key = "df4385c2-33de-e423-ca1f7b3ea8b7"`,
			want:  nil,
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

func TestDeepl_Verify(t *testing.T) {
	proKey := "df4385c2-33de-e423-4134-ca1f7b3ea8b7"
	freeKey := "279a2e9d-83b3-c416-7e2d-f721593e42a0:fx"
	adminKey := "a1b2c3d4-e5f6-7890-abcd-ef1234567890:adm"

	tests := []struct {
		name                string
		s                   Scanner
		input               string
		wantRaw             string
		wantVerified        bool
		wantVerificationErr bool
		wantExtra           map[string]string
	}{
		{
			name: "verified pro usage",
			s: Scanner{client: common.ConstantResponseHttpClient(200, `{
				"character_count": 42,
				"character_limit": 500000
			}`)},
			input:        `deepl_api_key = "` + proKey + `"`,
			wantRaw:      proKey,
			wantVerified: true,
			wantExtra: map[string]string{
				"type":            "pro",
				"character_count": "42",
				"character_limit": "500000",
			},
		},
		{
			name:         "verified free key",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `{"character_count":1,"character_limit":500000}`)},
			input:        "Authorization: DeepL-Auth-Key " + freeKey,
			wantRaw:      freeKey,
			wantVerified: true,
			wantExtra: map[string]string{
				"type":            "free",
				"character_count": "1",
				"character_limit": "500000",
			},
		},
		{
			name:         "verified admin key",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `[]`)},
			input:        "DEEPL_ADMIN_KEY=" + adminKey,
			wantRaw:      adminKey,
			wantVerified: true,
			wantExtra:    map[string]string{"type": "admin"},
		},
		{
			name:         "quota exceeded still verified",
			s:            Scanner{client: common.ConstantResponseHttpClient(456, `{"message":"Quota exceeded"}`)},
			input:        `deepl_api_key = "` + proKey + `"`,
			wantRaw:      proKey,
			wantVerified: true,
			wantExtra:    map[string]string{"type": "pro"},
		},
		{
			name:         "invalid key",
			s:            Scanner{client: common.ConstantResponseHttpClient(403, `{"message":"Wrong authorization"}`)},
			input:        `deepl_api_key = "` + proKey + `"`,
			wantRaw:      proKey,
			wantVerified: false,
		},
		{
			name: "scoped pro key missing usage scope is still live",
			s: Scanner{client: common.ConstantResponseHttpClient(403, `{
				"message": "Forbidden",
				"detail": "Missing required scope(s): usage:read"
			}`)},
			input:        `deepl_api_key = "` + proKey + `"`,
			wantRaw:      proKey,
			wantVerified: true,
			wantExtra:    map[string]string{"type": "pro", "scoped": "true"},
		},
		{
			name:         "free key 403 is invalid, not scoped",
			s:            Scanner{client: common.ConstantResponseHttpClient(403, `{"message":"Forbidden","detail":"Missing required scope(s): usage:read"}`)},
			input:        "Authorization: DeepL-Auth-Key " + freeKey,
			wantRaw:      freeKey,
			wantVerified: false,
		},
		{
			name:                "unexpected status",
			s:                   Scanner{client: common.ConstantResponseHttpClient(404, "")},
			input:               `deepl_api_key = "` + proKey + `"`,
			wantRaw:             proKey,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "timeout",
			s:                   Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			input:               `deepl_api_key = "` + proKey + `"`,
			wantRaw:             proKey,
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
			require.Equal(t, detector_typepb.DetectorType_DeepL, got.DetectorType)
			require.Equal(t, "DeepL", got.DetectorType.String())
			require.Equal(t, test.wantRaw, string(got.Raw))
			require.Equal(t, map[string]string{"key": test.wantRaw}, got.SecretParts)
			require.Equal(t, test.wantVerified, got.Verified)
			if test.wantVerificationErr {
				require.Error(t, got.VerificationError())
			} else {
				require.NoError(t, got.VerificationError())
			}
			if diff := cmp.Diff(test.wantExtra, got.ExtraData); diff != "" {
				t.Errorf("ExtraData diff: (-want +got)\n%s", diff)
			}
		})
	}
}
