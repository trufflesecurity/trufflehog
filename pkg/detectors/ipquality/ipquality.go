package ipquality

import (
	"context"
	"encoding/json"
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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ipquality"}) + `\b([0-9a-zA-Z]{32})\b`)
)

const (
	// response messages
	invalidKeyMessage         = "Invalid or unauthorized key"
	insufficientCreditMessage = "insufficient credits"
)

type apiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ipquality"}
}

// FromData will find and optionally verify Ipquality secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_IPQuality,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := verifyIPQualityAPIKey(ctx, client, resMatch)

			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_IPQuality
}

func (s Scanner) Description() string {
	return "IPQualityScore provides tools to detect and prevent fraudulent activity. IPQualityScore API keys can be used to access their fraud prevention services."
}

func verifyIPQualityAPIKey(ctx context.Context, client *http.Client, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://www.ipqualityscore.com/api/json/account/%s", apiKey), nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")

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
		var response apiResponse

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		if err = json.Unmarshal(bodyBytes, &response); err != nil {
			return false, err
		}

		switch response.Success {
		case true:
			return true, nil
		case false:
			/*
				for invalid api key and for a key which has insufficient credit the API returns the same response.
				The scenario where we have correct API key but it has insufficient credit is rare than a scenario that we capture
				an invalid api key as the pattern is too common. Hence in case we get insufficient credit error message we mark the
				API Key as inactive and send back a verification error as well.
			*/
			if strings.Contains(response.Message, insufficientCreditMessage) {
				return false, errors.New("couldn't verify; API Key has " + insufficientCreditMessage)
			} else if strings.Contains(response.Message, invalidKeyMessage) {
				return false, nil
			}
		}

		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
