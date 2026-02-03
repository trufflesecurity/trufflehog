package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// Response struct for decoding API responses.
type response struct {
	Data struct {
		LastLogin int `json:"lastLogin"`
	} `json:"data"`
}

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"harness"}) + `\b(pat\.[A-Za-z0-9]{22}\.[0-9a-f]{24}\.[A-Za-z0-9]{20})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"harness"}
}

// FromData will find and optionally verify Harness secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Harness,
			Raw:          []byte(match),
		}

		if verify {
			client := s.getClient()

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)

			if isVerified {
				s1.AnalysisInfo = map[string]string{
					"key": match,
				}
			}

		}

		results = append(results, s1)
	}

	return
}

/*
In the document, all of the APIs are required to provide API Key Token as header and
accountIdentifier as query parameter. Although, the below API returns successful response
without providing accountIdentifier as query parameter.
We may need to update this if Harness decides to enforce this in the future.
API Reference: https://apidocs.harness.io/tag/User/#operation/getCurrentUserInfo
*/
func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.harness.io/ng/api/user/currentUser", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("x-api-key", token)

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		extraData := make(map[string]string)
		var response response
		if err := json.NewDecoder(res.Body).Decode(&response); err == nil {
			extraData["last_login"] = strconv.Itoa(response.Data.LastLogin)
			return true, extraData, nil
		}
		return true, nil, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Harness
}

func (s Scanner) Description() string {
	return "Harness.io is an AI-driven CI/CD platform that automates software delivery, streamlining code building, testing, and deployment with intelligent optimization and multi-cloud support."
}
