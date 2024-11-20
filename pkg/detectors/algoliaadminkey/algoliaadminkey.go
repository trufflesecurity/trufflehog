package algoliaadminkey

import (
	"context"
	"fmt"
	"encoding/json"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"algolia", "docsearch", "apiKey"}) + `\b([a-zA-Z0-9]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"algolia", "docsearch", "appId"}) + `\b([A-Z0-9]{10})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"algolia", "docsearch"}
}

// FromData will find and optionally verify AlgoliaAdminKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AlgoliaAdminKey,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}

			if verify {
				// Verify if the key is a valid Algolia Admin Key.
				isVerified, verificationErr := verifyAlgoliaKey(ctx, resIdMatch, resMatch)

				// Verify if the key has sensitive permissions, even if it's not an Admin Key.
				if !isVerified {
					isVerified, verificationErr = verifyAlgoliaKeyACL(ctx, resIdMatch, resMatch)
				}

				s1.SetVerificationError(verificationErr, resMatch)
				s1.Verified = isVerified
			}

			results = append(results, s1)
		}
	}
	return results, nil
}

func verifyAlgoliaKey(ctx context.Context, appId, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+appId+"-dsn.algolia.net/1/keys", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("X-Algolia-Application-Id", appId)
	req.Header.Add("X-Algolia-API-Key", apiKey)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.StatusCode == 403 {
		return false, nil
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	return true, nil
}

func verifyAlgoliaKeyACL(ctx context.Context, appId, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+appId+".algolia.net/1/keys/"+apiKey, nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("X-Algolia-Application-Id", appId)
	req.Header.Add("X-Algolia-API-Key", apiKey)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.StatusCode == 403 {
		return false, nil
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	var jsonResponse struct {
		ACL []string `json:"acl"`
	}

	if err := json.NewDecoder(res.Body).Decode(&jsonResponse); err != nil {
		return false, err
	}

	for _, acl := range jsonResponse.ACL {
		if acl != "search" && acl != "listIndexes" && acl != "settings" {
			return true, nil // Other permissions are sensitive.
		}
	}

	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AlgoliaAdminKey
}

func (s Scanner) Description() string {
	return "Algolia is a search-as-a-service platform. Algolia Admin Keys can be used to manage indices and API keys, and perform administrative tasks."
}
