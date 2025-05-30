package adobeio

import (
	"context"
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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"adobe"}) + `\b([a-z0-9]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"adobe"}) + `\b([a-zA-Z0-9.]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"adobe"}
}

// FromData will find and optionally verify AdobeIO secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeys, uniqueIds = make(map[string]struct{}), make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	for _, matches := range idPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIds[matches[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		for id := range uniqueIds {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AdobeIO,
				Raw:          []byte(key),
				RawV2:        []byte(key + id),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyAdobeIOSecret(ctx, client, key, id)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

func verifyAdobeIOSecret(ctx context.Context, client *http.Client, key string, id string) (bool, error) {
	url := "https://stock.adobe.io/Rest/Media/1/Search/Files?locale=en_US%2526search_parameters%255Bwords%255D=kittens"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("x-api-key", key)
	req.Header.Add("x-product", id)

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
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AdobeIO
}

func (s Scanner) Description() string {
	return "AdobeIO provides APIs for integrating with Adobe services. These credentials can be used to access Adobe services and data."
}
