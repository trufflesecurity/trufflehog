package skybiometry

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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"skybiometry"}) + `\b([0-9a-z]{25,26})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"skybiometry"}) + `\b([0-9a-z]{25,26})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"skybiometry"}
}

// FromData will find and optionally verify SkyBiometry secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeyMatches, uniqueSecretMatches := make(map[string]struct{}), make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[match[1]] = struct{}{}
	}

	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[match[1]] = struct{}{}
	}

	for key := range uniqueKeyMatches {
		for secret := range uniqueSecretMatches {
			if key == secret {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SkyBiometry,
				Raw:          []byte(secret),
			}

			if verify {
				isVerified, verificationErr := verifySkyBiometery(ctx, client, key, secret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SkyBiometry
}

func (s Scanner) Description() string {
	return "SkyBiometry is a facial recognition service. SkyBiometry API keys can be used to access and utilize their facial recognition API."
}

func verifySkyBiometery(ctx context.Context, client *http.Client, apiKey, apiSecret string) (bool, error) {
	apiURL := fmt.Sprintf("https://api.skybiometry.com/fc/account/authenticate?api_key=%s&api_secret=%s", apiKey, apiSecret)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false, err
	}

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
	case http.StatusBadRequest, http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
