package instamojo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	// KeyPat is client_id
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"instamojo"}) + `\b([0-9a-zA-Z]{40})\b`)
	// Secretpat is Client_secret
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"instamojo"}) + `\b([0-9a-zA-Z]{128})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"instamojo"}
}

// FromData will find and optionally verify Instamojo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	clientIdmatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range secretMatches {
		resSecret := strings.TrimSpace(match[1])

		for _, clientIdMatch := range clientIdmatches {
			resClientId := strings.TrimSpace(clientIdMatch[1])

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Instamojo,
				Raw:          []byte(resClientId),
				SecretParts:  map[string]string{"key": resClientId},
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				isVerified, verificationErr := verifyInstamojo(ctx, client, resClientId, resSecret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resClientId, resSecret)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyInstamojo(ctx context.Context, client *http.Client, resClientId, resSecret string) (bool, error) {
	payload := strings.NewReader("grant_type=client_credentials&client_id=" + resClientId + "&client_secret=" + resSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.instamojo.com/oauth2/token/", payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}
	body := string(bodyBytes)
	if (res.StatusCode >= 200 && res.StatusCode < 300) && strings.Contains(body, "access_token") {
		return true, nil
	}

	return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Instamojo
}

func (s Scanner) Description() string {
	return "An Ecommerce service, API keys can be used to create and access customer data"
}
