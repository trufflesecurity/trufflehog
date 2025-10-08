package atlassian

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"gopkg.in/h2non/gock.v1"
)

func TestAtlassian_Pattern(t *testing.T) {
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
				[INFO] Sending request to the atlassian API
				[DEBUG] Using Key=ATCTT3xFfGN0GsZNgOGrQSHSnxiJVi00oHlRicyM0yMNuKCBfw6qOHVcCy4Hm89GnclGb_W-1qAkxqCn5XbuyoX54bNhpK5yFKGFR7ocV6FByvL_P9Sb3tFnbUg3T3I3S_RGCBLMSN7Nsa4GJv8JEJ6bzvDmX-oJ8AnrazMU-zZ5hb-u3t2ERew=366BFE3A
				[INFO] Response received: 200 OK
				`,
			want: []string{"ATCTT3xFfGN0GsZNgOGrQSHSnxiJVi00oHlRicyM0yMNuKCBfw6qOHVcCy4Hm89GnclGb_W-1qAkxqCn5XbuyoX54bNhpK5yFKGFR7ocV6FByvL_P9Sb3tFnbUg3T3I3S_RGCBLMSN7Nsa4GJv8JEJ6bzvDmX-oJ8AnrazMU-zZ5hb-u3t2ERew=366BFE3A"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{98651}</id>
  					<secret>{AQAAABAAA ATCTT3xFfGXc59Vkq40qLX=iEOIrJRZ}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"ATCTT3xFfGXc59Vkq40qLX=iEOIrJRZ"},
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

// TestAtlassian_AnalysisInfo_KeyAndOrgId tests if both the key and organization id are populated into AnalysisInfo
// given that they are present in the input data chunk
func TestAtlassian_AnalysisInfo_KeyAndOrgId(t *testing.T) {
	client := common.SaneHttpClient()
	d := Scanner{client: client}

	key := "ATCTT3xFfGN0GsZNgOGrQSHSnxiJVi00oHlRicyM0yMNuKCBfw6qOHVcCy4Hm89GnclGb_W-1qAkxqCn5XbuyoX54bNhpK5yFKGFR7ocV6FByvL_P9Sb3tFnbUg3T3I3S_RGCBLMSN7Nsa4GJv8JEJ6bzvDmX-oJ8AnrazMU-zZ5hb-u3t2ERew=366BFE3A"
	orgId := "123j4567-e89b-12d3-a456-426614174000"

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)
	gock.New("https://api.atlassian.com").
		Get("/admin/v1/orgs").
		MatchHeader("Accept", "application/json").
		MatchHeader("Authorization", fmt.Sprintf("Bearer %s", key)).
		Reply(http.StatusOK).
		JSON(map[string]any{
			"Data": []map[string]any{},
		})

	t.Run("key and organization id both present", func(t *testing.T) {
		input := fmt.Sprintf(`
		[INFO] Sending request to the atlassian API
		[DEBUG] Using Key=%s
		[DEBUG] Using Organization ID=%s
		[INFO] Response received: 200 OK
		`, key, orgId)

		results, err := d.FromData(context.Background(), true, []byte(input))
		require.NoError(t, err)
		require.Len(t, results, 1, "mismatch in result count: expected %d, got %d", 1, len(results))
		result := results[0]
		require.NotNil(t, result.AnalysisInfo, "AnalysisInfo is nil")

		assert.Equal(t, key, result.AnalysisInfo["key"], "mismatch in key")
		assert.Equal(t, orgId, result.AnalysisInfo["organization_id"], "mismatch in organization_id")
	})
}

// TestAtlassian_AnalysisInfo_KeyOnly tests if only key is populated into AnalysisInfo
// given that only the key and no organization_id is present in the input data chunk
func TestAtlassian_AnalysisInfo_KeyOnly(t *testing.T) {
	client := common.SaneHttpClient()
	d := Scanner{client: client}

	key := "ATCTT3xFfGN0GsZNgOGrQSHSnxiJVi00oHlRicyM0yMNuKCBfw6qOHVcCy4Hm89GnclGb_W-1qAkxqCn5XbuyoX54bNhpK5yFKGFR7ocV6FByvL_P9Sb3tFnbUg3T3I3S_RGCBLMSN7Nsa4GJv8JEJ6bzvDmX-oJ8AnrazMU-zZ5hb-u3t2ERew=366BFE3A"

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)
	gock.New("https://api.atlassian.com").
		Get("/admin/v1/orgs").
		MatchHeader("Accept", "application/json").
		MatchHeader("Authorization", fmt.Sprintf("Bearer %s", key)).
		Reply(http.StatusOK).
		JSON(map[string]any{
			"Data": []map[string]any{},
		})
	t.Run("only key present", func(t *testing.T) {

		input := fmt.Sprintf(`
		[INFO] Sending request to the atlassian API
		[DEBUG] Using Key=%s
		[INFO] Response received: 200 OK
		`, key)

		results, err := d.FromData(context.Background(), true, []byte(input))
		require.NoError(t, err)
		require.Len(t, results, 1, "mismatch in result count: expected %d, got %d", 1, len(results))
		result := results[0]
		require.NotNil(t, result.AnalysisInfo, "AnalysisInfo is nil")

		assert.Equal(t, key, result.AnalysisInfo["key"], "mismatch in key")
	})
}
