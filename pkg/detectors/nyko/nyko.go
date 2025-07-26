package nyko

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
	defaultClient = common.SaneHttpClient()
	keywords      = []string{"nyko", "nyko_api", "nyko_plat", "nyk", "nyk_", "nyko_platform"}
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat       = regexp.MustCompile(detectors.PrefixRegex(keywords) + `\b([0-9a-z-]{17})\b`)
	keySecretPat = regexp.MustCompile(detectors.PrefixRegex(keywords) + `\b([0-9a-z-]{18})\b`)
)

// FromData will find and optionally verify Nyko secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	
	uniqueKeySecrets := make(map[string]struct{})
	for _, match := range keySecretPat.FindAllStringSubmatch(dataStr, -1) {
		if len(match) > 1 {
			uniqueKeySecrets[match[1]] = struct{}{}
		}
	}

	for keySecret := range uniqueKeySecrets {
		for _, match := range keyMatches {
			if len(match) <= 1 {
				continue
			}
			apiKey := match[1]

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_NykoAPIKey,
				Raw:          []byte(apiKey),
			}

			if verify {
				client := defaultClient

				isVerified, verificationErr := verifyMatch(ctx, client, apiKey, keySecret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, apiKey)
			}

			results = append(results, s1)
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, apiKey, keySecret string) (bool, error) {
	// Replace this URL with the actual Nyko API endpoint for verification
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://nyko-api.onrender.com/v1/verify", http.NoBody)
	if err != nil {
		return false, nil
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-API-Secret", keySecret)

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
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NykoAPIKey
}

func (s Scanner) Description() string {
	return "NykoAPIKey is used to authenticate with Nyko services and APIs"
}