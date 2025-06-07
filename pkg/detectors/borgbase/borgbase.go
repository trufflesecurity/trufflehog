package borgbase

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"borgbase"}) + `\b([a-zA-Z0-9/_.-]{148,152})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"borgbase"}
}

// FromData will find and optionally verify Borgbase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Borgbase,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := verifyBorgbase(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Borgbase
}

func (s Scanner) Description() string {
	return "Borgbase is a service for hosting Borg repositories. Borgbase API keys can be used to manage and access these repositories."
}

// docs: https://docs.borgbase.com/api
func verifyBorgbase(ctx context.Context, client *http.Client, key string) (bool, error) {
	timeout := 10 * time.Second
	client.Timeout = timeout

	payload := strings.NewReader(`{"query":"{ sshList {id, name}}"}`)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.borgbase.com/graphql", payload)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

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
		validResponse := strings.Contains(bodyString, `"sshList":[]`)
		if validResponse {
			return true, nil
		}

		return false, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
