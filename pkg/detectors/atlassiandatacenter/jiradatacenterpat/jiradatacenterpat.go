package jiradatacenterpat

import (
	"context"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/atlassiandatacenter"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interfaces at compile time.
var (
	_ detectors.Detector                    = (*Scanner)(nil)
	_ detectors.EndpointCustomizer          = (*Scanner)(nil)
	_ detectors.MultiPartCredentialProvider = (*Scanner)(nil)
)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	keywords = []string{"jira", "atlassian"}

	// PATs are base64-encoded strings of the form <12-digit-id>:<20-random-bytes> (33 bytes, 44 chars, no padding).
	// Since the first byte is always an ASCII digit (0x30–0x39), the first base64 character is always M, N, or O.
	// This is also verified by generating 25+ tokens.
	// The trailing boundary (?:[^A-Za-z0-9+/=]|\z) is used instead of \b to correctly handle tokens ending in + or /.
	patPat  = atlassiandatacenter.GetDCTokenPat(keywords)
	urlPat  = atlassiandatacenter.GetURLPat(keywords)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return keywords
}

// FromData will find and optionally verify Jira Data Center PAT secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := make(map[string]struct{})
	for _, match := range patPat.FindAllStringSubmatch(dataStr, -1) {
		if atlassiandatacenter.IsStructuralPAT(match[1]) {
			tokens[match[1]] = struct{}{}
		}
	}

	endpoints := atlassiandatacenter.FindEndpoints(dataStr, urlPat, s.Endpoints)

	for token := range tokens {
		if len(endpoints) == 0 {
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_JiraDataCenterPAT,
				Raw:          []byte(token),
				SecretParts:  map[string]string{"token": token},
				Redacted:     token[:3] + "..." + token[len(token)-3:],
				ExtraData:    map[string]string{"message": "No Jira Data Center URL was found or configured. To verify this token, set the Jira instance base URL as a custom endpoint."},
			})
			continue
		}

		for _, endpoint := range endpoints {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_JiraDataCenterPAT,
				Raw:          []byte(token),
				SecretParts: map[string]string{
					"token": token,
					"url":   endpoint,
				},
				RawV2:    []byte(token + ":" + endpoint),
				Redacted: token[:3] + "..." + token[len(token)-3:],
			}

			if verify {
				isVerified, extraData, verificationErr := verifyPAT(ctx, s.getClient(), endpoint, token)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, token)
			}

			results = append(results, s1)

			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

// verifyPAT checks whether the token is valid by calling the /rest/api/2/myself endpoint,
// which returns the currently authenticated user.
// Docs: https://developer.atlassian.com/server/jira/platform/rest/v10002/api-group-myself/#api-api-2-myself-get
func verifyPAT(ctx context.Context, client *http.Client, baseURL, token string) (bool, map[string]string, error) {
	u, err := detectors.ParseURLAndStripPathAndParams(baseURL)
	if err != nil {
		return false, nil, err
	}
	u.Path = "/rest/api/2/myself"

	isVerified, body, err := atlassiandatacenter.MakeVerifyRequest(ctx, client, u.String(), token)
	if err != nil || !isVerified {
		return isVerified, nil, err
	}

	extraData := map[string]string{"endpoint": baseURL}
	if name, ok := body["displayName"].(string); ok {
		extraData["display_name"] = name
	}
	if email, ok := body["emailAddress"].(string); ok {
		extraData["email_address"] = email
	}
	return true, extraData, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_JiraDataCenterPAT
}

func (s Scanner) Description() string {
	return "Jira Data Center is a self-hosted version of Jira. Personal Access Tokens (PATs) are used to authenticate API requests to Jira Data Center instances."
}
