package ayrshare

import (
	"context"
	"encoding/json"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ayrshare"}) + `\b([A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ayrshare"}
}

// FromData will find and optionally verify Ayrshare secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Ayrshare,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, extraData, err := verifyMatch(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(err, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, key string) (bool, map[string]string, error) {
	// Reference: https://www.ayrshare.com/docs/apis/user/profile-details
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.ayrshare.com/api/user", http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, nil, err
		}
		var responseBody map[string]any
		if err := json.Unmarshal(bodyBytes, &responseBody); err == nil {
			if email, ok := responseBody["email"].(string); ok {
				return true, map[string]string{"email": email}, nil
			}
		}
		return true, nil, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	case http.StatusForbidden:
		// Invalid Bearer tokens get a 403 Forbidden response despite what is stated in the docs.
		// Documentation: https://www.ayrshare.com/docs/errors/errors-http
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, nil, err
		}
		if strings.Contains(string(bodyBytes), "API Key not valid") {
			return false, nil, nil
		}
	}
	return false, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Ayrshare
}

func (s Scanner) Description() string {
	return "Ayrshare provides social media management services. Ayrshare API keys can be used to manage social media accounts and posts."
}
