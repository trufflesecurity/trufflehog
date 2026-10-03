package boxoauth

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

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
		wantCount   int
		wantRawV2   string
		wantMatched bool
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
			wantCount:   1,
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

func TestBoxOauth_AnalysisInfo_VerifiedWithValidSubjectId(t *testing.T) {
	client := common.SaneHttpClient()
	d := Scanner{client: client}

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)

	// Mock 1: verifyMatch → valid pair (400 with "unauthorized_client")
	gock.New("https://api.box.com").
		Post("/oauth2/token").
		Reply(http.StatusBadRequest).
		BodyString(`{"error":"unauthorized_client","error_description":"The grant type is unauthorized for this client_id"}`)

	// Mock 2: verifySubjectID enterprise attempt → success (200)
	gock.New("https://api.box.com").
		Post("/oauth2/token").
		Reply(http.StatusOK).
		BodyString(`{"access_token":"test_token","expires_in":4169,"token_type":"bearer"}`)

	input := fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId)

	results, err := d.FromData(context.Background(), true, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.True(t, r.Verified)
	require.NotNil(t, r.SecretParts)
	assert.Equal(t, clientId, r.SecretParts["client_id"])
	assert.Equal(t, clientSecret, r.SecretParts["client_secret"])
	assert.Equal(t, subjectId, r.SecretParts["subject_id"])
}

func TestBoxOauth_AnalysisInfo_VerifiedNoSubjectId(t *testing.T) {
	client := common.SaneHttpClient()
	d := Scanner{client: client}

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)

	// Mock: verifyMatch → valid pair
	gock.New("https://api.box.com").
		Post("/oauth2/token").
		Reply(http.StatusBadRequest).
		BodyString(`{"error":"unauthorized_client","error_description":"The grant type is unauthorized for this client_id"}`)

	input := fmt.Sprintf("box id = '%s' box secret = '%s'", clientId, clientSecret)

	results, err := d.FromData(context.Background(), true, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.True(t, r.Verified)
	require.NotNil(t, r.SecretParts)
	assert.Equal(t, clientId, r.SecretParts["client_id"])
	assert.Equal(t, clientSecret, r.SecretParts["client_secret"])
	assert.Empty(t, r.SecretParts["subject_id"])
}

func TestBoxOauth_AnalysisInfo_VerifiedInvalidSubjectId(t *testing.T) {
	client := common.SaneHttpClient()
	d := Scanner{client: client}

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)

	// Mock 1: verifyMatch → valid pair
	gock.New("https://api.box.com").
		Post("/oauth2/token").
		Reply(http.StatusBadRequest).
		BodyString(`{"error":"unauthorized_client","error_description":"The grant type is unauthorized for this client_id"}`)

	// Mock 2: verifySubjectID enterprise attempt → fail (400)
	gock.New("https://api.box.com").
		Post("/oauth2/token").
		Reply(http.StatusBadRequest).
		BodyString(`{"error":"invalid_grant","error_description":"Cannot obtain token based on the enterprise configuration for your app"}`)

	// Mock 3: verifySubjectID user attempt → fail (400)
	gock.New("https://api.box.com").
		Post("/oauth2/token").
		Reply(http.StatusBadRequest).
		BodyString(`{"error":"invalid_grant","error_description":"Cannot obtain token based on the enterprise configuration for your app"}`)

	input := fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId)

	results, err := d.FromData(context.Background(), true, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.True(t, r.Verified)
	require.NotNil(t, r.SecretParts)
	assert.Equal(t, clientId, r.SecretParts["client_id"])
	assert.Equal(t, clientSecret, r.SecretParts["client_secret"])
	assert.Empty(t, r.SecretParts["subject_id"])
}

func TestBoxOauth_AnalysisInfo_UnverifiedWithSubjectId(t *testing.T) {
	client := common.SaneHttpClient()
	d := Scanner{client: client}

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)

	// Mock: verifyMatch → invalid pair (400 with "invalid_client")
	gock.New("https://api.box.com").
		Post("/oauth2/token").
		Reply(http.StatusBadRequest).
		BodyString(`{"error":"invalid_client","error_description":"The client_id is invalid"}`)

	input := fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId)

	results, err := d.FromData(context.Background(), true, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.False(t, r.Verified)
	require.NotNil(t, r.SecretParts)
	assert.Equal(t, clientId, r.SecretParts["client_id"])
	assert.Equal(t, clientSecret, r.SecretParts["client_secret"])
	assert.Empty(t, r.SecretParts["subject_id"])
}
