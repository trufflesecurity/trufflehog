package circleci

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

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
var _ detectors.Versioner = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"circle"}) + `([a-fA-F0-9]{40})`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

func (Scanner) Version() int { return 1 }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"circle"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Circle
}

func (s Scanner) Description() string {
	return "CircleCI is a continuous integration and delivery platform used to build, test, and deploy software. CircleCI tokens can be used to interact with the CircleCI API and access various resources and functionalities."
}

// FromData will find and optionally verify Circle secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens = make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Circle,
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"Version": strconv.Itoa(s.Version()),
			},
		}

		if verify {
			// https://circleci.com/docs/api/#authentication
			isVerified, verificationErr := VerifyCircleCIToken(ctx, s.getClient(), token)
			result.Verified = isVerified
			result.SetVerificationError(verificationErr, token)
		}

		results = append(results, result)
	}

	return
}

func VerifyCircleCIToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://circleci.com/api/v2/me", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Accept", "application/json;")
	req.Header.Add("Circle-Token", token)

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
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
