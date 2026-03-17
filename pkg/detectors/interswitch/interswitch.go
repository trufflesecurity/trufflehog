package interswitch

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var (
	interswitchKeyPattern = regexp.MustCompile(`(?:interswitch|quickteller)[_-]?(?:api[_-])?(?:key|secret)["\s:=]+([0-9a-zA-Z]{32,})|macKey["']?\s*[:=]\s*["']?([0-9A-Fa-f]{64})`)
	interswitchClient     = common.SaneHttpClient()
)

type scanner struct{}

var _ detectors.Detector = (*scanner)(nil)

func (s scanner) Keywords() []string {
	return []string{"interswitch", "quickteller", "interswitchk", "macKey"}
}

func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := interswitchKeyPattern.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) < 1 {
			continue
		}

		key := match[0]
		if len(match) > 1 && match[1] != "" {
			key = match[1]
		} else if len(match) > 2 && match[2] != "" {
			key = match[2]
		}

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Interswitch,
			Raw:          []byte(key),
		}

		if verify {
			verified, verifyErr := verifyInterswitchKey(ctx, key)
			s.Verified = verified
			if verifyErr != nil {
				s.SetVerificationError(verifyErr, key)
			}
		}

		results = append(results, s)
	}

	return results, nil
}

func verifyInterswitchKey(ctx context.Context, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.interswitchng.com/api/v1/merchant/profile", nil)
	if err != nil {
		return false, err
	}

	auth := base64.StdEncoding.EncodeToString([]byte(key + ":"))
	req.Header.Add("Authorization", "Basic "+auth)
	req.Header.Add("Content-Type", "application/json")

	resp, err := interswitchClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		if bytes.Contains(bodyBytes, []byte("invalid")) || bytes.Contains(bodyBytes, []byte("unauthorized")) {
			return false, nil
		}
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (s scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Interswitch
}

func (s scanner) Description() string {
	return "Detects Interswitch API keys and MAC keys"
}