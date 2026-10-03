package square

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// there are a few endpoints we can check, but merchants seems the least sensitive.
	verifyURL = "https://connect.squareupsandbox.com/v2/merchants"

	// more context to be added if this is too generic
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"square"}) + `(EAAA[a-zA-Z0-9\-_+=]{60})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"EAAA"}
}

// FromData will find and optionally verify Square secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Surprisingly there are still a lot of false positives! So, also doing substring check for square.
	if !strings.Contains(strings.ToLower(dataStr), "square") {
		return
	}

	secMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	for _, secMatch := range secMatches {
		resMatch := strings.TrimSpace(secMatch[1])

		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Square,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}
		result.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/square/",
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, resMatch)
			result.Verified = isVerified
			result.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, result)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")
	// unclear if this version needs to be set or matters, seems to work without, but docs want it
	// req.Header.Add("Square-Version", "2020-08-12")

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
		// good key and has `merchants` scope - default allowed by square
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	case http.StatusForbidden:
		// A 403 only proves the key is valid when Square itself says the scope is insufficient.
		// Anything else may come from a TLS-intercepting proxy or Square's edge (rate limiting, bot protection).
		body := readBody(res)
		if hasErrorCode(body, "INSUFFICIENT_SCOPES") {
			return true, nil
		}
		return false, fmt.Errorf("unexpected 403 from Square: %s", truncateBody(body))
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d: %s", res.StatusCode, truncateBody(readBody(res)))
	}
}

// squareErrorResponse is Square's error envelope for non-2xx responses.
// See https://developer.squareup.com/docs/build-basics/handling-errors.
type squareErrorResponse struct {
	Errors []struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Detail   string `json:"detail"`
	} `json:"errors"`
}

const (
	maxBodySize      = 4 << 10 // cap how much of the response body we read
	maxErrorBodySize = 512     // cap how much of the body we put in an error
)

func readBody(res *http.Response) []byte {
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxBodySize))
	return body
}

func hasErrorCode(body []byte, code string) bool {
	var apiErr squareErrorResponse
	if err := json.Unmarshal(body, &apiErr); err != nil {
		return false
	}
	for _, e := range apiErr.Errors {
		if e.Code == code {
			return true
		}
	}
	return false
}

// truncateBody collapses whitespace and caps the body so an HTML block page doesn't flood the output.
func truncateBody(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if s == "" {
		return "<empty body>"
	}
	if len(s) > maxErrorBodySize {
		return s[:maxErrorBodySize] + "..."
	}
	return s
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Square
}

func (s Scanner) Description() string {
	return "Square is a financial services and mobile payment company. Square API keys can be used to access and manage payments, transactions, and other financial data."
}
