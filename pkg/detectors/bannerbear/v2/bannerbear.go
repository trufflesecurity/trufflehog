package bannerbear

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

func (s Scanner) Version() int { return 2 }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(bb_(?:pr|ma)_[a-f0-9]{30})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bb_pr_", "bb_ma_"}
}

// FromData will find and optionally verify Bannerbear secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	uniqueMatches := make(map[string]struct{}, len(matches))

	for _, match := range matches {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Bannerbear,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			isVerified, extraData, verificationErr := s.verifyBannerBear(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bannerbear
}

func (s Scanner) Description() string {
	return "Bannerbear is an API for generating dynamic images, videos, and GIFs. Bannerbear API keys can be used to access and manipulate these resources."
}

// docs: https://developers.bannerbear.com/
func (s Scanner) verifyBannerBear(ctx context.Context, client *http.Client, key string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.bannerbear.com/v2/auth", http.NoBody)
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	extraData := map[string]string{"version": fmt.Sprintf("%d", s.Version())}

	switch resp.StatusCode {
	case http.StatusOK:
		extraData["key_type"] = "Project API Key"
		return true, extraData, nil
	case http.StatusBadRequest:
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, extraData, err
		}

		// According to Bannerbear API docs (https://developers.bannerbear.com/#authentication), the /auth endpoint
		// expects us to add a project_id parameter to the payload, when using a Full Access Master API Key.
		// otherwise, it returns a 400 Bad Request with "Error: When using a Master API Key you must set a project_id parameter"
		// Also, when we use a Master API Key with limited access, it returns a 400 Bad Request with "Error: this Master Key is Limited Access only"
		validResponse := bytes.Contains(bodyBytes, []byte("When using a Master API Key")) || bytes.Contains(bodyBytes, []byte("Master Key is Limited Access"))
		if validResponse {
			extraData["key_type"] = "Master API Key"
			return true, extraData, nil
		} else {
			return false, extraData, fmt.Errorf("bad request: %s, body: %s", resp.Status, string(bodyBytes))
		}
	case http.StatusUnauthorized:
		return false, extraData, nil
	default:
		return false, extraData, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
