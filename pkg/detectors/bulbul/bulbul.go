package bulbul

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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bulbul"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bulbul"}
}

// FromData will find and optionally verify Bulbul secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Bulbul,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := verifyBulbul(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bulbul
}

func (s Scanner) Description() string {
	return "Bulbul is an API service. Bulbul API keys can be used to access and modify data within the service."
}

// docs: https://docs.jungleworks.com/bulbul/bulbul-api-details
func verifyBulbul(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://prod-api.bulbul.io/view_all_users?api_key=%s", key), nil)
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
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, `"message":"Successful",`) {
			return true, nil
		} else {
			return false, nil
		}
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
