package atlassiandatacenter

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// Real-format sample PATs that decode to "<numeric id>:<random bytes>".
const (
	// Jira DC sample.
	jiraToken = "NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M"

	// Confluence DC samples.
	confluenceToken1 = "NTk3MjQzOTIyNTAwOtFOuTsHRIp1E81GApKpC2xpEzfz"
	confluenceToken2 = "NDc4MjM3OTUxMzk2OopoSkTDTnBcWIw0Wa4bico9zOLK"

	// 44-char base64 that starts with [MNO] (passes the regex) but decodes
	// to bytes with no colon — must be rejected by IsStructuralPAT.
	nonStructural = "MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestIsStructuralPAT(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		want      bool
	}{
		{
			name:      "valid real Jira token",
			candidate: jiraToken,
			want:      true,
		},
		{
			name:      "valid real Confluence token 1",
			candidate: confluenceToken1,
			want:      true,
		},
		{
			name:      "valid real Confluence token 2",
			candidate: confluenceToken2,
			want:      true,
		},
		{
			name:      "valid - digits before colon",
			candidate: encode([]byte("123456789012:01234567890123456789")),
			want:      true,
		},
		{
			name:      "invalid base64",
			candidate: "!!!not-base64!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
			want:      false,
		},
		{
			name:      "no colon in decoded bytes",
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
			// decodes to "0a:xxx..." — 'a' is not a digit
			name:      "non-digit before colon",
			candidate: "MGE6eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
			want:      false,
		},
		{
			name:      "non-structural: passes regex but no colon in decoded bytes",
			candidate: nonStructural,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsStructuralPAT(tt.candidate))
		})
	}
}

func TestGetDCTokenPat(t *testing.T) {
	pat := GetDCTokenPat([]string{"jira", "atlassian"})

	// Known-valid token — must match and capture exactly the token (no trailing char).
	m := pat.FindStringSubmatch("jira token: " + jiraToken)
	require.NotNil(t, m, "expected a match")
	assert.Equal(t, jiraToken, m[1], "captured group should be exactly the token")

	// Token followed by newline — must match and NOT capture the newline.
	m2 := pat.FindStringSubmatch("jira token: " + jiraToken + "\n")
	require.NotNil(t, m2)
	assert.Equal(t, jiraToken, m2[1], "captured group must not include the trailing newline")

	// Token starts with 'A' — not M/N/O — must not match.
	assert.Nil(t, pat.FindStringSubmatch("jira token: ATg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M"))

	// Token followed by base64 padding — trailing boundary must reject it.
	assert.Nil(t, pat.FindStringSubmatch("jira token: "+jiraToken+"="))

	// Token followed by more base64 chars — must not match (longer string).
	assert.Nil(t, pat.FindStringSubmatch("jira token: "+jiraToken+"AAAA"))
}

func TestFindEndpoints(t *testing.T) {
	urlPat := GetURLPat([]string{"jira", "atlassian"})

	// identity resolver: returns exactly what it receives (simulates UseFoundEndpoints only)
	identity := func(urls ...string) []string { return urls }

	tests := []struct {
		name    string
		data    string
		resolve func(...string) []string
		want    []string
	}{
		{
			name:    "URL near keyword is returned",
			data:    "jira url: https://jira.corp.com",
			resolve: identity,
			want:    []string{"https://jira.corp.com"},
		},
		{
			name:    "URL not near any keyword is ignored",
			data:    "unrelated url: https://example.com",
			resolve: identity,
			want:    []string{},
		},
		{
			name:    "duplicate URLs in data are deduplicated",
			data:    "jira: https://jira.corp.com\natlassian: https://jira.corp.com",
			resolve: identity,
			want:    []string{"https://jira.corp.com"},
		},
		{
			name:    "trailing slash is stripped",
			data:    "jira url: https://jira.corp.com/",
			resolve: identity,
			want:    []string{"https://jira.corp.com"},
		},
		{
			name:    "URL with port is accepted",
			data:    "jira url: https://jira.corp.com:8443",
			resolve: identity,
			want:    []string{"https://jira.corp.com:8443"},
		},
		{
			name:    "multiple distinct URLs are all returned",
			data:    "jira prod: https://jira.prod.com\natlassian staging: https://jira.staging.com",
			resolve: identity,
			want:    []string{"https://jira.prod.com", "https://jira.staging.com"},
		},
		{
			name: "resolve can inject configured endpoints not in data",
			data: "no urls here but jira keyword present",
			resolve: func(urls ...string) []string {
				return append(urls, "https://configured.jira.com")
			},
			want: []string{"https://configured.jira.com"},
		},
		{
			name: "resolve can filter out URLs",
			data: "jira url: https://jira.corp.com",
			resolve: func(urls ...string) []string {
				return []string{} // simulate UseFoundEndpoints(false) with no configured endpoint
			},
			want: []string{},
		},
		{
			name:    "no data returns empty slice",
			data:    "",
			resolve: identity,
			want:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindEndpoints(tt.data, urlPat, tt.resolve)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestMakeVerifyRequest(t *testing.T) {
	const testURL = "http://dc.example.com/rest/api/test"
	const testToken = "NTg4OTI1Mzk1OTA1OiBb9S4WPEoK6cmOe6pq6VO0lt6M"

	t.Run("200: verified=true, body decoded", func(t *testing.T) {
		client := common.SaneHttpClient()
		defer gock.Off()
		defer gock.RestoreClient(client)
		gock.InterceptClient(client)

		gock.New("http://dc.example.com").
			Get("/rest/api/test").
			MatchHeader("Authorization", "Bearer "+testToken).
			MatchHeader("Accept", "application/json").
			Reply(http.StatusOK).
			JSON(map[string]any{"displayName": "Alice", "emailAddress": "alice@example.com"})

		verified, body, err := MakeVerifyRequest(context.Background(), client, testURL, testToken)
		require.NoError(t, err)
		assert.True(t, verified)
		require.NotNil(t, body)
		assert.Equal(t, "Alice", body["displayName"])
		assert.Equal(t, "alice@example.com", body["emailAddress"])
	})

	t.Run("200: verified=true, body nil when response is not JSON", func(t *testing.T) {
		client := common.SaneHttpClient()
		defer gock.Off()
		defer gock.RestoreClient(client)
		gock.InterceptClient(client)

		gock.New("http://dc.example.com").
			Get("/rest/api/test").
			Reply(http.StatusOK).
			BodyString("not json")

		verified, body, err := MakeVerifyRequest(context.Background(), client, testURL, testToken)
		require.NoError(t, err)
		assert.True(t, verified)
		assert.Nil(t, body)
	})

	t.Run("401: verified=false, no error", func(t *testing.T) {
		client := common.SaneHttpClient()
		defer gock.Off()
		defer gock.RestoreClient(client)
		gock.InterceptClient(client)

		gock.New("http://dc.example.com").
			Get("/rest/api/test").
			Reply(http.StatusUnauthorized)

		verified, body, err := MakeVerifyRequest(context.Background(), client, testURL, testToken)
		require.NoError(t, err)
		assert.False(t, verified)
		assert.Nil(t, body)
	})

	t.Run("unexpected status: verified=false, error returned", func(t *testing.T) {
		client := common.SaneHttpClient()
		defer gock.Off()
		defer gock.RestoreClient(client)
		gock.InterceptClient(client)

		gock.New("http://dc.example.com").
			Get("/rest/api/test").
			Reply(http.StatusInternalServerError)

		verified, body, err := MakeVerifyRequest(context.Background(), client, testURL, testToken)
		require.Error(t, err)
		assert.False(t, verified)
		assert.Nil(t, body)
	})

	t.Run("uses GET method", func(t *testing.T) {
		client := common.SaneHttpClient()
		defer gock.Off()
		defer gock.RestoreClient(client)
		gock.InterceptClient(client)

		// gock.Get only matches GET; a POST would not match and would error.
		gock.New("http://dc.example.com").
			Get("/rest/api/test").
			Reply(http.StatusOK)

		_, _, err := MakeVerifyRequest(context.Background(), client, testURL, testToken)
		require.NoError(t, err)
		assert.True(t, gock.IsDone(), "gock interceptor was not matched — request may not have been GET")
	})

	t.Run("propagates network error", func(t *testing.T) {
		client := common.SaneHttpClient()
		defer gock.Off()
		defer gock.RestoreClient(client)
		gock.InterceptClient(client)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately to force a network error

		verified, body, err := MakeVerifyRequest(ctx, client, testURL, testToken)
		assert.Error(t, err)
		assert.False(t, verified)
		assert.Nil(t, body)
	})
}
