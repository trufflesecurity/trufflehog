package lambdatest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{
		"hub.lambdatest.com",
		"userName",
		"\"username\":",
		"USER_NAME",
		"user",
		"lambdatestUser",
		"LT_USERNAME",
		"LAMBDATEST_USERNAME",
	}) + `\b([a-zA-Z0-9]+)\b`)

	accessKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{
		"hub.lambdatest.com",
		"accessKey",
		"\"access_Key\":",
		"ACCESS_KEY",
		"key",
		"lambdatestKey",
		"LT_AUTHKEY",
		"LT_ACCESS_KEY",
	}) + `\b(LT_[a-zA-Z0-9]{47})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"lambdatest"}
}

// FromData will find and optionally verify Lambdatest secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	uniqueUsernameMatches := make(map[string]struct{})
	for _, match := range usernamePat.FindAllStringSubmatch(dataStr, -1) {
		uniqueUsernameMatches[match[1]] = struct{}{}
	}

	uniqueAccessKeyMatches := make(map[string]struct{})
	for _, match := range accessKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAccessKeyMatches[match[1]] = struct{}{}
	}
	for usernameMatch := range uniqueUsernameMatches {
		for accessKeyMatch := range uniqueAccessKeyMatches {

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_LambdaTest,
				Raw:            []byte(accessKeyMatch),
				RawV2:        []byte(fmt.Sprintf("%s:%s", usernameMatch, accessKeyMatch)),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, usernameMatch, accessKeyMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, usernameMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, usernameMatch string, accessKeyMatch string) (bool, error) {
	body := map[string]string{
		"username": usernameMatch,
		"token":    accessKeyMatch,
	}

	// encode the body as JSON
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://auth.lambdatest.com/api/user/token/auth", bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		// If the endpoint returns useful information, we can return it as a map.
		return true, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LambdaTest
}

func (s Scanner) Description() string {
	return "LambdaTest is a cloud-based cross-browser testing platform that allows developers to test their web applications across various browsers and devices."
}
