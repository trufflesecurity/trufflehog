package remita

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var (
	remitaKeyPattern = regexp.MustCompile(`remita[_-]?(?:api[_-])?key["\s:=]+([0-9a-zA-Z]{32,})`)
	remitaClient     = common.SaneHttpClient()
)

type scanner struct{}

var _ detectors.Detector = (*scanner)(nil)

func (s scanner) Keywords() []string {
	return []string{"remita", "remita_api_key", "remita_merchant"}
}

func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := remitaKeyPattern.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		key := match[1]

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Remita,
			Raw:          []byte(key),
		}

		if verify {
			isVerified := verifyRemitaKey(ctx, key)
			s.Verified = isVerified
		}

		results = append(results, s)
	}

	return results, nil
}

func verifyRemitaKey(ctx context.Context, key string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.remita.net/v1/send/api/echo", nil)
	if err != nil {
		return false
	}

	auth := base64.StdEncoding.EncodeToString([]byte(key + ":"))
	req.Header.Add("Authorization", "Basic "+auth)
	req.Header.Add("Content-Type", "application/json")

	resp, err := remitaClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// Valid response: 200 OK and no "invalid"/"unauthorized" keywords
	if resp.StatusCode == 200 {
		if !bytes.Contains(bodyBytes, []byte("invalid")) && !bytes.Contains(bodyBytes, []byte("unauthorized")) {
			return true
		}
	}

	// Invalid responses
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}

	// 2xx responses without error keywords = valid
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true
	}

	return false
}

func (s scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Remita
}

func (s scanner) Description() string {
	return "Detects Remita API keys and merchant credentials"
}