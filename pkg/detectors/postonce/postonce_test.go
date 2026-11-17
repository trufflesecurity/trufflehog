package postonce

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	validKey      = "po_live_3f9a1c7e_8b2d4e6f0a1c3e5b7d9f1a2c4e6b8d0f2a4c6e8b0d2f4a6c"
	otherValidKey = "po_live_0d4e8a2b_5c7e9a1b3d5f7c9e1a3b5d7f9c1e3a5b7d9f1c3e5a7b9d1f"
)

func TestPostOnce_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] Sending request to the PostOnce API
				[DEBUG] Authorization: Bearer ` + validKey + `
				[INFO] Response received: 200 OK
			`,
			want: []string{validKey},
		},
		{
			name:  "valid pattern - env file",
			input: `POSTONCE_API_KEY=` + validKey,
			want:  []string{validKey},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
					<scope>GLOBAL</scope>
					<id>{postonce}</id>
					<secret>{AQAAABAAA ` + validKey + `}</secret>
					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{validKey},
		},
		{
			name: "finds all matches",
			input: `
				POSTONCE_API_KEY=` + validKey + `
				POSTONCE_STAGING_KEY="` + otherValidKey + `"
			`,
			want: []string{validKey, otherValidKey},
		},
		{
			name:  "invalid pattern - uppercase hex",
			input: `POSTONCE_API_KEY=po_live_3F9A1C7E_8B2D4E6F0A1C3E5B7D9F1A2C4E6B8D0F2A4C6E8B0D2F4A6C`,
			want:  nil,
		},
		{
			name:  "invalid pattern - secret too short",
			input: `POSTONCE_API_KEY=po_live_3f9a1c7e_8b2d4e6f0a1c3e5b7d9f1a2c4e6b8d0f2a4c6e8b0d2f4a`,
			want:  nil,
		},
		{
			name:  "invalid pattern - secret too long",
			input: `POSTONCE_API_KEY=po_live_3f9a1c7e_8b2d4e6f0a1c3e5b7d9f1a2c4e6b8d0f2a4c6e8b0d2f4a6c8e`,
			want:  nil,
		},
		{
			name:  "invalid pattern - documentation placeholder",
			input: `curl -H "Authorization: Bearer po_live_xxxxx_xxxxx" https://postonce.to/api/public/v1/accounts`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
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

func TestPostOnce_Verification(t *testing.T) {
	tests := []struct {
		name                string
		status              int
		body                string
		wantVerified        bool
		wantExtraData       map[string]string
		wantVerificationErr bool
	}{
		{
			name:         "200 is verified",
			status:       200,
			body:         `{"data":[]}`,
			wantVerified: true,
		},
		{
			name:   "401 is determinately unverified",
			status: 401,
			body:   `{"error":{"code":"invalid_api_key","message":"Invalid API key."}}`,
		},
		{
			name:          "403 missing scope is verified",
			status:        403,
			body:          `{"error":{"code":"missing_scope","message":"Missing required scope: accounts:read"}}`,
			wantVerified:  true,
			wantExtraData: map[string]string{"restriction": "missing_scope"},
		},
		{
			name:          "403 plan not allowed is verified",
			status:        403,
			body:          `{"error":{"code":"plan_not_allowed","message":"Public API access is not on this plan."}}`,
			wantVerified:  true,
			wantExtraData: map[string]string{"restriction": "plan_not_allowed"},
		},
		{
			name:                "403 with unknown code is indeterminate",
			status:              403,
			body:                `<html>Forbidden</html>`,
			wantVerificationErr: true,
		},
		{
			name:                "429 is indeterminate",
			status:              429,
			body:                `{"error":{"code":"rate_limited"}}`,
			wantVerificationErr: true,
		},
		{
			name:                "500 is indeterminate",
			status:              500,
			body:                ``,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: common.ConstantResponseHttpClient(test.status, test.body)}
			results, err := s.FromData(context.Background(), true, []byte("POSTONCE_API_KEY="+validKey))
			require.NoError(t, err)
			require.Len(t, results, 1)

			r := results[0]
			require.Equal(t, test.wantVerified, r.Verified)
			require.Equal(t, test.wantVerificationErr, r.VerificationError() != nil)
			require.Equal(t, map[string]string{"key": validKey}, r.SecretParts)
			if diff := cmp.Diff(test.wantExtraData, r.ExtraData); diff != "" {
				t.Errorf("extra data diff: (-want +got)\n%s", diff)
			}
		})
	}
}
