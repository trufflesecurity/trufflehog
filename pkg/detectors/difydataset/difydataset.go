package difydataset

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// dataset-<24 alphanumeric chars>, e.g. dataset-t8IMtmhWzulciBpTMRMTqwa4
	keyPat = regexp.MustCompile(`\b(dataset-[a-zA-Z0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"dataset-"}
}

// FromData will find and optionally verify Dify Knowledge Base (dataset) API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DifyDataset,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.dify.ai/v1/datasets", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

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
		// Determinate success: key is live and can list the account's knowledge bases.
		return true, nil, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Determinate failure: key is invalid/revoked. No error object.
		return false, nil, nil
	default:
		// Indeterminate: unexpected status (rate limit, 5xx, etc).
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DifyDataset
}

func (s Scanner) Description() string {
	return "Dify is an LLM app development platform. This is a Dify Knowledge Base API key (also called a dataset key), which grants access to every knowledge base visible to the account that created it, so a leaked key has a broad blast radius."
}