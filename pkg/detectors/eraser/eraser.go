package eraser

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

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"eraser"}) + `\b([0-9a-zA-Z]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"eraser"}
}

// FromData will find and optionally verify Eraser secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Eraser,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/eraser/",
			},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// https://docs.eraser.io/reference/generate-diagram-from-eraser-dsl
	payload := strings.NewReader("{\"elements\":[{\"type\":\"diagram\"}]}")

	url := "https://app.eraser.io/api/render/elements"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return false, nil, err
	}

	req.Header = http.Header{"Authorization": []string{"Bearer " + token}}
	req.Header.Add("content-type", "application/json")

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
		return true, nil, nil
	case http.StatusUnauthorized:
		// 401 API token unauthorized
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		// 400 The request is missing the 'text' parameter
		// 500 Eraser was unable to generate a result
		// 503 Service temporarily unavailable. This may be the result of too many requests.
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Eraser
}

func (s Scanner) Description() string {
	return "Eraser is a tool used for generating diagrams from DSL. Eraser API tokens can be used to authenticate and interact with the Eraser API."
}
