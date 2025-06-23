package langsmith

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
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})\b`) // personal api token and service keys
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"lsv2_pt_", "lsv2_sk_"}
}

// FromData will find and optionally verify Langsmith secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueAPIKeys := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPIKeys[match[1]] = struct{}{}
	}

	for apiKey := range uniqueAPIKeys {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LangSmith,
			Raw:          []byte(apiKey),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, apiKey)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, apiKey)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.smith.langchain.com/api/v1/api-key", http.NoBody)
	if err != nil {
		return false, nil
	}

	req.Header.Set("X-API-Key", apiKey)

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
	return detectorspb.DetectorType_LangSmith
}

func (s Scanner) Description() string {
	return "LangSmith is a unified observability & evals platform where teams can debug, test, and monitor AI app performance — whether building with LangChain or not"
}
