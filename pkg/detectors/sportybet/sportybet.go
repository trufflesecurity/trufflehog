package sportybet

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

var (
	sportybetKeyPattern = regexp.MustCompile(`(?i)sportybet[_-]?(?:api[_-])?(?:key|token)["\s:=]+([0-9a-zA-Z]{32,})`)
	sportybetClient     = common.SaneHttpClient()
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

func (s Scanner) Keywords() []string {
	return []string{"sportybet", "sportybet_api", "sporty_api_key"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := sportybetKeyPattern.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		key := match[1]

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Sportybet,
			Raw:          []byte(key),
		}

		if verify {
			verified, verifyErr := verifySportybetKey(ctx, key)
			s.Verified = verified
			if verifyErr != nil {
				s.SetVerificationError(verifyErr, key)
			}
		}

		results = append(results, s)
	}

	return results, nil
}

func verifySportybetKey(ctx context.Context, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sportybet.com/api/v2/user/account", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Content-Type", "application/json")

	resp, err := sportybetClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
    return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Sportybet
}

func (s Scanner) Description() string {
	return "Detects SportyBet/BetKing API tokens and credentials"
}
