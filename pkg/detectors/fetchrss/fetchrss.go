package fetchrss

import (
	"context"
	"encoding/json"
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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"fetchrss"}) + `\b([a-zA-Z0-9.]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"fetchrss"}
}

// FromData will find and optionally verify Fetchrss secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Fetchrss,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			verified, verificationErr := verifyToken(ctx, client, token)
			s1.Verified = verified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fetchrss.com/api/v1/feed/list?auth="+token, nil)
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// The API seems to always return a 200 status code.
	// See: https://fetchrss.com/developers
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	var apiRes response
	if err := json.NewDecoder(res.Body).Decode(&apiRes); err != nil {
		return false, err
	}

	if apiRes.Success {
		// The key is valid.
		return true, nil
	} else if apiRes.Error.Code == 401 {
		// The key is invalid.
		return false, nil
	} else {
		return false, fmt.Errorf("unexpected error: [code=%d, message=%s]", apiRes.Error.Code, apiRes.Error.Message)
	}
}

type response struct {
	Success bool `json:"success"`
	Error   struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Fetchrss
}

func (s Scanner) Description() string {
	return "FetchRSS is a service used to convert web content into RSS feeds. FetchRSS API keys can be used to manage and access these feeds."
}
