package billomat

import (
	"context"
	"errors"
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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"billomat"}) + `\b([0-9a-z]{4,20})\b`) // the Billomat ID must be between 4 and 20 characters long.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"billomat"}) + `\b([0-9a-f]{32})\b`)

	errAccountIDNotFound = errors.New("account id not found")
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"billomat"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Billomat
}

func (s Scanner) Description() string {
	return "Billomat is an online invoicing software. Billomat API keys can be used to access and manage invoices, clients, and other related data."
}

// FromData will find and optionally verify Billomat secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueIDs, uniqueAPIKeys = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIDs[match[1]] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPIKeys[match[1]] = struct{}{}
	}

	for apiKey := range uniqueAPIKeys {
		for id := range uniqueIDs {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Billomat,
				Raw:          []byte(apiKey),
				RawV2:        []byte(apiKey + id),
			}

			if verify {
				isVerified, verificationErr := verifyBillomat(ctx, client, id, apiKey)
				s1.Verified = isVerified
				if verificationErr != nil {
					// remove the account ID if not found to prevent reuse during other API key checks.
					if errors.Is(verificationErr, errAccountIDNotFound) {
						delete(uniqueIDs, id)
						continue
					}

					s1.SetVerificationError(verificationErr, apiKey)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

// docs: https://www.billomat.com/en/api/basics/authentication/
func verifyBillomat(ctx context.Context, client *http.Client, id, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s.billomat.net/api/v2/clients/myself", id), http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-BillomatApiKey", key)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	case http.StatusNotFound: // billomat api returns 404 if account id does not exist
		// read the full response body
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, nil
		}

		/*
			The regex for capturing a Billomat ID is prone to false positives.
			To minimize incorrect matches, we return an error if the captured account ID does not exist,
			as this likely indicates the match was invalid.
		*/
		if strings.Contains(string(bodyBytes), "account not found") {
			return false, errAccountIDNotFound
		}

		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
