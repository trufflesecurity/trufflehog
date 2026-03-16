package sportybet

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type scanner struct{}

var _ detectors.Detector = (*scanner)(nil)

func (s scanner) Keywords() []string {
	return []string{"sportybet", "sportybet_api", "sporty_api_key", "betking", "betting", "Bearer"}
}

func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	rx := regexp.MustCompile(`sportybet[_-]?(?:api[_-])?(?:key|token)["\s:=]+([0-9a-zA-Z]{32,})|eyJ[A-Za-z0-9-_]{100,}|Bearer [A-Za-z0-9-_]{50,}\.[A-Za-z0-9-_]{50,}\.[A-Za-z0-9-_]{50,}`)
	matches := rx.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) < 1 {
			continue
		}

		key := match[0]
		if len(match) > 1 && match[1] != "" {
			key = match[1]
		}

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

	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
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