package boxoauth

import (
	"context"
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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	clientIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"id"}) + `\b([a-zA-Z0-9]{32})\b`)
	clientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"secret"}) + `\b([a-zA-Z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"box"}
}

func (s Scanner) Description() string {
	return "Box is a service offering various service for secure collaboration, content management, and workflow. Box Oauth credentials can be used to access and interact with this data."
}

// FromData will find and optionally verify Box secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueIdMatches := make(map[string]struct{})
	for _, match := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIdMatches[match[1]] = struct{}{}
	}

	uniqueSecretMatches := make(map[string]struct{})
	for _, match := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[match[1]] = struct{}{}
	}

	for resIdMatch := range uniqueIdMatches {
		for resSecretMatch := range uniqueSecretMatches {

			// ignore if the id and secret are the same
			if resIdMatch == resSecretMatch {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_BoxOauth,
				Raw:          []byte(resIdMatch),
				RawV2:        []byte(resIdMatch + resSecretMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, extraData, verificationErr := verifyMatch(ctx, client, resIdMatch, resSecretMatch)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, resIdMatch)
			}

			results = append(results, s1)

			// box client supportes only one client id and secret pair
			if s1.Verified {
				break
			}
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, id string, secret string) (bool, map[string]string, error) {
	url := "https://api.box.com/oauth2/token"
	payload := strings.NewReader("grant_type=client_credentials&client_id=" + id + "&client_secret=" + secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return false, nil, nil
	}

	req.Header = http.Header{"content-type": []string{"application/x-www-form-urlencoded"}}

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// We are using malformed request to check if the client id and secret are correct
	// box oauth api returns 400 status code even if they are correct
	// so we need to check the response body for the error message with 'unauthorized_client' keyword
	// or if invalid_client keyword is present then the client id & secret are incorrect
	switch res.StatusCode {
	case http.StatusBadRequest:
		{
			bodyBytes, err := io.ReadAll(res.Body)
			if err != nil {
				return false, nil, err
			}
			body := string(bodyBytes)

			if strings.Contains(body, "unauthorized_client") {
				return true, nil, nil
			}

			return false, nil, nil
		}
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BoxOauth
}
