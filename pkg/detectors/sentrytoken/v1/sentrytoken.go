package sentrytoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sentry"}) + `\b([a-f0-9]{64})\b`)

	forbiddenError = "You do not have permission to perform this action."
)

func (s Scanner) Version() int {
	return 1
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sentry"}
}

// FromData will find and optionally verify SentryToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// find all unique auth tokens
	var uniqueAuthTokens = make(map[string]struct{})

	for _, authToken := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAuthTokens[authToken[1]] = struct{}{}
	}

	for authToken := range uniqueAuthTokens {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SentryToken,
			Raw:          []byte(authToken),
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}
			extraData, isVerified, verificationErr := VerifyToken(ctx, s.client, authToken)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, authToken)
			s1.ExtraData = extraData
		}

		results = append(results, s1)
	}

	return results, nil
}

func VerifyToken(ctx context.Context, client *http.Client, token string) (map[string]string, bool, error) {
	// api docs: https://docs.sentry.io/api/organizations/
	// this api will return 200 for user auth tokens with scope of org:<>
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://sentry.io/api/0/organizations/", nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var organizations []Organization
		if err = json.NewDecoder(resp.Body).Decode(&organizations); err != nil {
			return nil, false, err
		}

		var extraData = make(map[string]string)
		for _, org := range organizations {
			extraData[fmt.Sprintf("orginzation_%s", org.ID)] = org.Name
		}

		return extraData, true, nil
	case http.StatusForbidden:
		var APIResp interface{}
		if err = json.NewDecoder(resp.Body).Decode(&APIResp); err != nil {
			return nil, false, err
		}

		// if response contain the forbiddenError message it means the token is active but does not have the right scope for this API call
		if strings.Contains(fmt.Sprintf("%v", APIResp), forbiddenError) {
			return nil, true, nil
		}

		return nil, false, nil
	case http.StatusUnauthorized:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SentryToken
}

func (s Scanner) Description() string {
	return "Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry."
}
