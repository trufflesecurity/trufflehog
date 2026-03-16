package sportybet

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type scanner struct{}

var _ detectors.Detector = (*scanner)(nil)

func (s scanner) Keywords() []string {
	return []string{"sportybet", "sportybet_api", "sporty_api_key"}
}

func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	rx := regexp.MustCompile(`sportybet[_-]?(?:api[_-])?(?:key|token)["\s:=]+([0-9a-zA-Z]{32,})`)
	matches := rx.FindAllStringSubmatch(dataStr, -1)

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
			isVerified := verifySportybetKey(ctx, key)
			s.Verified = isVerified
		}

		results = append(results, s)
	}

	return results, nil
}

func verifySportybetKey(ctx context.Context, key string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sportybet.com/api/v2/user/account", nil)
	if err != nil {
		return false
	}

	// Strip "Bearer " prefix if present
	token := strings.TrimPrefix(key, "Bearer ")

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := common.SaneHttpClient().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if resp.StatusCode == 200 && !bytes.Contains(bodyBytes, []byte("error")) {
		return true
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 || bytes.Contains(bodyBytes, []byte("invalid")) || bytes.Contains(bodyBytes, []byte("unauthorized")) {
		return false
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true
	}

	return false
}

func (s scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Sportybet
}

func (s scanner) Description() string {
	return "Detects SportyBet/BetKing API tokens and credentials"
}