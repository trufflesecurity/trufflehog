package confluencedatacenter

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Real-format sample PATs: each decodes to "<numeric id>:<random bytes>".
const (
	validPAT1 = "NTk3MjQzOTIyNTAwOtFOuTsHRIp1E81GApKpC2xpEzfz"
	validPAT2 = "NDc4MjM3OTUxMzk2OopoSkTDTnBcWIw0Wa4bico9zOLK"
	// 44-char base64 that passes tokenPat (leading [MNO]) but decodes to
	// bytes with no colon, so it must be rejected by isStructuralPAT rather
	// than by the regex. Exercises the structural post-filter's reject path.
	nonStructural = "MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func TestConfluenceDataCenter_Pattern(t *testing.T) {
	d := Scanner{}
	d.UseFoundEndpoints(true)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "token + instance URL in one chunk",
			input: fmt.Sprintf(`
				CONFLUENCE_URL=https://wiki.example.com:8443
				confluence_token=%s
			`, validPAT1),
			want: []string{validPAT1 + ":https://wiki.example.com:8443"},
		},
		{
			name: "token + REST API URL pattern",
			input: fmt.Sprintf(`
				# confluence bearer token: %s
				confluence host: https://confluence.corp.local/rest/api/user/current
			`, validPAT1),
			want: []string{validPAT1 + ":https://confluence.corp.local"},
		},
		{
			name: "token with no URL in context (token-only)",
			input: fmt.Sprintf(`
				# confluence personal access token for CI
				TOKEN=%s
			`, validPAT2),
			want: []string{validPAT2},
		},
		{
			name: "structural post-filter rejects non-PAT base64",
			input: fmt.Sprintf(`
				confluence key: %s
			`, nonStructural),
			want: []string{},
		},
		{
			name: "multiple tokens + multiple URLs => Cartesian product",
			input: fmt.Sprintf(`
				confluence prod: https://wiki.prod.corp/wiki/
				confluence stg:  https://wiki.stg.corp/rest/api
				confluence_a=%s
				confluence_b=%s
			`, validPAT1, validPAT2),
			want: []string{
				validPAT1 + ":https://wiki.prod.corp",
				validPAT1 + ":https://wiki.stg.corp",
				validPAT2 + ":https://wiki.prod.corp",
				validPAT2 + ":https://wiki.stg.corp",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matched := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matched) == 0 {
				t.Fatalf("keywords %v not matched by aho-corasick in input", d.Keywords())
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Fatalf("mismatch in result count: expected %d, got %d (%+v)", len(test.want), len(results), results)
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

func TestConfluenceDataCenter_Verification(t *testing.T) {
	const baseURL = "https://wiki.internal.corp"

	cases := []struct {
		name          string
		status        int
		wantVerified  bool
		wantVerifyErr bool
	}{
		{"200 verified", http.StatusOK, true, false},
		{"401 invalid", http.StatusUnauthorized, false, false},
		{"403 unexpected", http.StatusForbidden, false, true},
		{"500 unknown", http.StatusInternalServerError, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := common.SaneHttpClient()
			d := Scanner{client: client}
			d.UseFoundEndpoints(true)

			defer gock.Off()
			defer gock.RestoreClient(client)
			gock.InterceptClient(client)

			gock.New(baseURL).
				Get("/rest/api/user/current").
				MatchHeader("Authorization", "Bearer "+validPAT1).
				Reply(tc.status)

			input := fmt.Sprintf("confluence url=%s\nconfluence token=%s\n", baseURL, validPAT1)

			results, err := d.FromData(context.Background(), true, []byte(input))
			require.NoError(t, err)
			require.Len(t, results, 1)

			r := results[0]
			assert.Equal(t, tc.wantVerified, r.Verified)
			if tc.wantVerifyErr {
				assert.Error(t, r.VerificationError())
			} else {
				assert.NoError(t, r.VerificationError())
			}
		})
	}
}
