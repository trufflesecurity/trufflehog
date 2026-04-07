package jiradatacenterpat

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	testToken    = "NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M"
	testEndpoint = "http://jira.example.com"
)

func TestJiraDataCenterPAT_Pattern(t *testing.T) {
	d := Scanner{}
	d.SetConfiguredEndpoints("https://jira.example.com")
	d.UseFoundEndpoints(true)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid PAT",
			input: `jira_token: NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M`,
			want:  []string{"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6Mhttps://jira.example.com"},
		},
		{
			name:  "URL found near jira keyword",
			input: `# jira server: http://jira.internal:8080` + "\n" + `jira token: NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M`,
			want: []string{
				"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6Mhttp://jira.internal:8080",
				"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6Mhttps://jira.example.com",
			},
		},
		{
			name:  "URL found near atlassian keyword",
			input: `# atlassian server: http://jira.internal:8080` + "\n" + `atlassian token: NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M`,
			want: []string{
				"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6Mhttp://jira.internal:8080",
				"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6Mhttps://jira.example.com",
			},
		},
		{
			name:  "too short - not a match",
			input: `jira_token: NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0`,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
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

func TestJiraDataCenterPAT_FromData(t *testing.T) {
	client := common.SaneHttpClient()

	d := Scanner{client: client}
	d.SetConfiguredEndpoints(testEndpoint)
	d.UseFoundEndpoints(false)

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)

	tests := []struct {
		name                string
		setup               func()
		data                string
		verify              bool
		wantResults         int
		wantVerified        bool
		wantVerificationErr bool
		wantExtraData       map[string]string
	}{
		{
			name: "found, verified",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/2/myself").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusOK).
					JSON(map[string]any{
						"displayName":  "Test User",
						"emailAddress": "test@example.com",
					})
			},
			data:         fmt.Sprintf("jira token: %s", testToken),
			verify:       true,
			wantResults:  1,
			wantVerified: true,
			wantExtraData: map[string]string{
				"display_name":  "Test User",
				"email_address": "test@example.com",
			},
		},
		{
			name: "found, unverified (401)",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/2/myself").
					Reply(http.StatusUnauthorized)
			},
			data:         fmt.Sprintf("jira token: %s", testToken),
			verify:       true,
			wantResults:  1,
			wantVerified: false,
		},
		{
			name:        "not found",
			setup:       func() {},
			data:        "jira config: nothing here",
			verify:      true,
			wantResults: 0,
		},
		{
			name: "found, verification error on unexpected status",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/2/myself").
					Reply(http.StatusInternalServerError)
			},
			data:                fmt.Sprintf("jira token: %s", testToken),
			verify:              true,
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name: "found, verification error on timeout",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/2/myself").
					Reply(http.StatusOK).
					Delay(2 * time.Second)
			},
			data:                fmt.Sprintf("jira token: %s", testToken),
			verify:              true,
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:         "found, no verify",
			setup:        func() {},
			data:         fmt.Sprintf("jira token: %s", testToken),
			verify:       false,
			wantResults:  1,
			wantVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gock.Flush()
			tt.setup()

			ctx := context.Background()
			if tt.wantVerificationErr {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}

			results, err := d.FromData(ctx, tt.verify, []byte(tt.data))
			require.NoError(t, err)
			require.Len(t, results, tt.wantResults)

			for _, result := range results {
				assert.Equal(t, detectorspb.DetectorType_JiraDataCenterPAT, result.DetectorType)
				assert.NotEmpty(t, result.Raw)
				assert.Equal(t, tt.wantVerified, result.Verified)
				assert.Equal(t, tt.wantVerificationErr, result.VerificationError() != nil)
				if tt.wantExtraData != nil {
					assert.Equal(t, tt.wantExtraData, result.ExtraData)
				}
			}
		})
	}
}
