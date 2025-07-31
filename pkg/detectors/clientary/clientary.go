/*
RoninApp rebranded to Clientary

Article: https://www.clientary.com/articles/a-new-brand/
*/
package clientary

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ronin", "clientary"}) + `\b([0-9a-zA-Z]{24,26})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"ronin", "clientary"}) + `\b([0-9Aa-zA-Z-]{4,25})\b`)

	errAccountNotFound = errors.New("account not found")
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ronin", "clientary"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Clientary
}

func (s Scanner) Description() string {
	return "Clientary is a one software app to manage Clients, Invoices, Projects, Proposals, Estimates, Hours, Payments, Contractors and Staff. Clientary keys can be used to access and manage invoices and other resources."
}

// FromData will find and optionally verify RoninApp secrets in a given set of bytes.
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
			// since regex matches can overlap, continue only if both apiKey and id are the same.
			if apiKey == id {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Clientary,
				Raw:          []byte(apiKey),
				RawV2:        []byte(apiKey + ":" + id),
				ExtraData:    make(map[string]string),
			}

			if verify {
				isVerified, verificationErr := verifyClientaryAPIKey(ctx, client, id, apiKey)
				s1.Verified = isVerified
				if verificationErr != nil {
					// remove the account ID if not found to prevent reuse during other API key checks.
					if errors.Is(verificationErr, errAccountNotFound) {
						delete(uniqueIDs, id)
						continue
					}

					s1.SetVerificationError(verificationErr, apiKey)
				}

				// If a verified result is found, attach rebranding documentation to inform the user about the RoninApp rebranding to Clientary.
				if s1.Verified {
					s1.ExtraData["Rebrading Docs"] = "https://www.clientary.com/articles/a-new-brand/"
				}
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

// docs: https://www.clientary.com/api
func verifyClientaryAPIKey(ctx context.Context, client *http.Client, id, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+id+".clientary.com/api/v2/invoices", http.NoBody)
	if err != nil {
		return false, nil
	}

	req.SetBasicAuth(apiKey, apiKey)
	req.Header.Add("Accept", "application/json")

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
	case http.StatusForbidden, http.StatusUnauthorized:
		return false, nil
	case http.StatusNotFound:
		// API return 404 if the account id does not exist
		return false, errAccountNotFound
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
