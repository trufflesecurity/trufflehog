package jiradatacenterpat

import (
	"context"
	"encoding/base64"
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
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const (
	testToken    = "NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M"
	testEndpoint = "http://jira.example.com"
)

func TestJiraDataCenterPAT_Pattern(t *testing.T) {
	d := Scanner{}
	_ = d.SetConfiguredEndpoints("https://jira.example.com")
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
			want:  []string{"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M:https://jira.example.com"},
		},
		{
			name:  "URL found near jira keyword",
			input: `# jira server: http://jira.internal:8080` + "\n" + `jira token: NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M`,
			want: []string{
				"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M:http://jira.internal:8080",
				"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M:https://jira.example.com",
			},
		},
		{
			name:  "URL found near atlassian keyword",
			input: `# atlassian server: http://jira.internal:8080` + "\n" + `atlassian token: NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M`,
			want: []string{
				"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M:http://jira.internal:8080",
				"NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M:https://jira.example.com",
			},
		},
		{
			name:  "valid PAT ending with +",
			input: `jira_token: MzE3MjgzNDMyNTczOmTaXorACdDy8aVJU6FotdRcz2y+`,
			want:  []string{"MzE3MjgzNDMyNTczOmTaXorACdDy8aVJU6FotdRcz2y+:https://jira.example.com"},
		},
		{
			name:  "not a match - invalid first character",
			input: `jira_token: ATg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M`,
			want:  []string{},
		},
		{
			name:  "not a match - substring of longer base64 string",
			input: `jira_token: MzE3MjgzNDMyNTczOmTaXorACdDy8aVJU6FotdRcz2y+AAAA`,
			want:  []string{},
		},
		{
			name:  "not a match - followed by base64 padding",
			input: `jira_token: NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M=`,
			want:  []string{},
		},
		{
			name:  "too short - not a match",
			input: `jira_token: NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0`,
			want:  []string{},
		},
		{
			// Passes the regex (44 chars, starts with M) but decodes to "0a:xxx..."
			// where the byte before the colon is not purely digits.
			name:  "not a match - fails structural check",
			input: `jira_token: MGE6eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4`,
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
	_ = d.SetConfiguredEndpoints(testEndpoint)
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
						"endpoint":     testEndpoint,
					})
			},
			data:         fmt.Sprintf("jira token: %s", testToken),
			verify:       true,
			wantResults:  1,
			wantVerified: true,
			wantExtraData: map[string]string{
				"display_name":  "Test User",
				"email_address": "test@example.com",
				"endpoint":      testEndpoint,
			},
		},
		{
			name: "found, verified - invalid json body",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/2/myself").
					Reply(http.StatusOK).
					BodyString("not json")
			},
			data:         fmt.Sprintf("jira token: %s", testToken),
			verify:       true,
			wantResults:  1,
			wantVerified: true,
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
				assert.Equal(t, detector_typepb.DetectorType_JiraDataCenterPAT, result.DetectorType)
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

func TestIsStructuralPAT(t *testing.T) {
	encode := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

	// helper to build a 33-byte payload with a numeric id and random suffix
	numericIDPayload := func(id, suffix string) []byte {
		return []byte(id + ":" + suffix)
	}

	tests := []struct {
		name      string
		candidate string
		want      bool
	}{
		{
			name:      "valid real token",
			candidate: testToken,
			want:      true,
		},
		{
			name:      "valid - digits before colon",
			candidate: encode(numericIDPayload("123456789012", "01234567890123456789")),
			want:      true,
		},
		{
			name:      "invalid base64",
			candidate: "!!!not-base64!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
			want:      false,
		},
		{
			name:      "no colon",
			candidate: encode([]byte("588925395905012345678901234567890")),
			want:      false,
		},
		{
			name:      "colon at position 0",
			candidate: encode([]byte(":01234567890123456789012345678901")),
			want:      false,
		},
		{
			name:      "colon at last position",
			candidate: encode([]byte("58892539590501234567890123456789:")),
			want:      false,
		},
		{
			name: "non-digit before colon",
			// decodes to "0a:xxx..." — 'a' is not a digit
			candidate: "MGE6eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isStructuralPAT(tt.candidate))
		})
	}
}

func TestJiraDataCenterPAT_NoURL(t *testing.T) {
	d := Scanner{client: common.SaneHttpClient()}

	results, err := d.FromData(context.Background(), true, []byte(fmt.Sprintf("jira token: %s", testToken)))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Verified)
	assert.Equal(t, map[string]string{"message": "No Jira Data Center URL was found or configured. To verify this token, set the Jira instance base URL as a custom endpoint."}, results[0].ExtraData)
	assert.Empty(t, results[0].RawV2)
}
