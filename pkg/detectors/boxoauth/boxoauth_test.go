package boxoauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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

// tokenMock describes one expected request to Box's token endpoint and the
// reply it gets. bodyPattern is a regular expression matched against the
// form-encoded request body; an empty pattern matches any request.
type tokenMock struct {
	bodyPattern string
	status      int
	body        string
}

const (
	unauthorizedClientBody = `{"error":"unauthorized_client","error_description":"The grant type is unauthorized for this client_id"}`
	invalidClientBody      = `{"error":"invalid_client","error_description":"The client credentials are not valid"}`
	invalidGrantBody       = `{"error":"invalid_grant","error_description":"Cannot obtain token based on the enterprise configuration for your app"}`
	tokenBody              = `{"access_token":"test_token","expires_in":3600,"token_type":"bearer"}`
)

// subjectRequest matches a subject-ID token request for one subject type.
// url.Values encodes keys in sorted order, so box_subject_id precedes
// box_subject_type in the body.
func subjectRequest(subjectID, subjectType string) string {
	return "box_subject_id=" + subjectID + "&box_subject_type=" + subjectType
}

// TestBoxOauth_Verification covers each of Box's verification rules. Every case
// registers exactly the requests it expects, in order, and fails if any mock is
// left unused or any other request is made. That also guarantees the detector
// never calls /oauth2/revoke.
func TestBoxOauth_Verification(t *testing.T) {
	failedSubjectAttempts := func(n int) []tokenMock {
		mocks := make([]tokenMock, n)
		for i := range mocks {
			mocks[i] = tokenMock{status: http.StatusBadRequest, body: invalidGrantBody}
		}
		return mocks
	}

	manyUserIDs := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "user_id = '%d'\n", 1000001+i)
		}
		return b.String()
	}

	tests := []struct {
		name          string
		input         string
		mocks         []tokenMock
		wantVerified  bool
		wantSubjectID string
		// wantErr is a substring of the verification error, or "" for no error.
		wantErr       string
		wantErrAbsent string
	}{
		{
			name:  "invalid_client is unverified with no subject requests",
			input: fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId),
			mocks: []tokenMock{
				{status: http.StatusBadRequest, body: invalidClientBody},
			},
		},
		{
			name:  "unauthorized_client with no subject ID is unknown",
			input: fmt.Sprintf("box id = '%s' box secret = '%s'", clientId, clientSecret),
			mocks: []tokenMock{
				{status: http.StatusBadRequest, body: unauthorizedClientBody},
			},
			wantErr:       "unauthorized_client",
			wantErrAbsent: "no nearby subject ID was accepted",
		},
		{
			name:  "enterprise subject token verifies the pair",
			input: fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId),
			mocks: []tokenMock{
				{status: http.StatusBadRequest, body: unauthorizedClientBody},
				{bodyPattern: subjectRequest(subjectId, "enterprise"), status: http.StatusOK, body: tokenBody},
			},
			wantVerified:  true,
			wantSubjectID: subjectId,
		},
		{
			name:  "user subject token verifies the pair after enterprise fails",
			input: fmt.Sprintf("box id = '%s' box secret = '%s' user = '%s'", clientId, clientSecret, subjectId),
			mocks: []tokenMock{
				{status: http.StatusBadRequest, body: unauthorizedClientBody},
				{bodyPattern: subjectRequest(subjectId, "enterprise"), status: http.StatusBadRequest, body: invalidGrantBody},
				{bodyPattern: subjectRequest(subjectId, "user"), status: http.StatusOK, body: tokenBody},
			},
			wantVerified:  true,
			wantSubjectID: subjectId,
		},
		{
			name:  "unauthorized_client with every subject attempt failing is unknown",
			input: fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId),
			mocks: append(
				[]tokenMock{{status: http.StatusBadRequest, body: unauthorizedClientBody}},
				failedSubjectAttempts(2)...,
			),
			wantErr:       "no nearby subject ID was accepted",
			wantErrAbsent: "subject ID candidates",
		},
		{
			name:  "unexpected status is unknown with no subject requests",
			input: fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId),
			mocks: []tokenMock{
				{status: http.StatusInternalServerError, body: `{}`},
			},
			wantErr: "unexpected HTTP response status 500",
		},
		{
			name:  "unexpected token error is unknown with no subject requests",
			input: fmt.Sprintf("box id = '%s' box secret = '%s' enterprise = '%s'", clientId, clientSecret, subjectId),
			mocks: []tokenMock{
				{status: http.StatusBadRequest, body: `{"error":"invalid_request","error_description":"Invalid grant_type parameter or parameter missing"}`},
			},
			wantErr: `unexpected token error "invalid_request"`,
		},
		{
			name:  "subject candidates are capped and truncation is reported",
			input: fmt.Sprintf("box id = '%s' box secret = '%s'\n%s", clientId, clientSecret, manyUserIDs(maxSubjectIDCandidates+2)),
			mocks: append(
				[]tokenMock{{status: http.StatusBadRequest, body: unauthorizedClientBody}},
				failedSubjectAttempts(maxSubjectIDCandidates*len(subjectTypes))...,
			),
			wantErr: fmt.Sprintf("tried %d of %d subject ID candidates", maxSubjectIDCandidates, maxSubjectIDCandidates+2),
		},
		{
			name:  "no truncation is reported when the pair verifies",
			input: fmt.Sprintf("box id = '%s' box secret = '%s'\n%s", clientId, clientSecret, manyUserIDs(maxSubjectIDCandidates+2)),
			mocks: []tokenMock{
				{status: http.StatusBadRequest, body: unauthorizedClientBody},
				{bodyPattern: subjectRequest("1000001", "enterprise"), status: http.StatusOK, body: tokenBody},
			},
			wantVerified:  true,
			wantSubjectID: "1000001",
		},
		{
			name: "strongly labeled subject ID is tried before an earlier weak one",
			input: fmt.Sprintf("box id = '%s' box secret = '%s' user = '%s' enterprise_id = '%s'",
				clientId, clientSecret, subjectId, subjectId2),
			mocks: []tokenMock{
				{status: http.StatusBadRequest, body: unauthorizedClientBody},
				{bodyPattern: subjectRequest(subjectId2, "enterprise"), status: http.StatusOK, body: tokenBody},
			},
			wantVerified:  true,
			wantSubjectID: subjectId2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := common.SaneHttpClient()
			d := Scanner{client: client}

			defer gock.OffAll()
			defer gock.RestoreClient(client)
			gock.InterceptClient(client)

			for _, m := range tt.mocks {
				req := gock.New("https://api.box.com").Post("/oauth2/token")
				if m.bodyPattern != "" {
					req = req.MatchType("url").BodyString(m.bodyPattern)
				}
				req.Reply(m.status).BodyString(m.body)
			}

			results, err := d.FromData(context.Background(), true, []byte(tt.input))
			require.NoError(t, err)
			require.Len(t, results, 1)

			r := results[0]
			assert.Equal(t, tt.wantVerified, r.Verified)
			assert.Equal(t, clientId, r.SecretParts["client_id"])
			assert.Equal(t, clientSecret, r.SecretParts["client_secret"])
			assert.Equal(t, tt.wantSubjectID, r.SecretParts["subject_id"])

			if tt.wantErr == "" {
				assert.NoError(t, r.VerificationError())
			} else {
				require.Error(t, r.VerificationError())
				assert.Contains(t, r.VerificationError().Error(), tt.wantErr)
			}
			if tt.wantErrAbsent != "" && r.VerificationError() != nil {
				assert.NotContains(t, r.VerificationError().Error(), tt.wantErrAbsent)
			}

			assert.True(t, gock.IsDone(), "expected every mocked request to be made")
			assert.False(t, gock.HasUnmatchedRequest(), "unexpected requests: %v", gock.GetUnmatchedRequests())
		})
	}
}

func TestRankSubjectIDs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "no candidates",
			input: "box id = 'abc'",
			want:  []string{},
		},
		{
			name:  "strong labels first, appearance order within each group",
			input: "user = '3333333' subject = '1111111' enterprise_id = '2222222' BOX_SUBJECT_ID = '4444444'",
			want:  []string{"2222222", "4444444", "3333333", "1111111"},
		},
		{
			name:  "number seen under weak and strong labels counts as strong",
			input: "user = '5555555' user = '6666666' enterprise = '5555555'",
			want:  []string{"5555555", "6666666"},
		},
		{
			name:  "duplicates are dropped",
			input: "user = '7777777' user = '7777777'",
			want:  []string{"7777777"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rankSubjectIDs(tt.input))
		})
	}
}
