package flutterwave

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type scanner struct{}

var _ detectors.Detector = (*scanner)(nil)

func (s scanner) Keywords() []string {
	return []string{"flutterwave", "flw_test", "flw_live", "FLWSECK"}
}

func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	rx := regexp.MustCompile(`flw_(test|live)_[0-9a-zA-Z]{50,}|FLWSECK[_-]?[a-zA-Z0-9]{30,}`)
	matches := rx.FindAllString(dataStr, -1)

	for _, match := range matches {
		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Flutterwave,
			Raw:          []byte(match),
		}

		if verify {
			isVerified := verifyFlutterwaveKey(ctx, match)
			s.Verified = isVerified
		}

		results = append(results, s)
	}

	return results, nil
}

func verifyFlutterwaveKey(ctx context.Context, key string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.flutterwave.com/v3/merchants", nil)
	if err != nil {
		return false
	}

	req.Header.Add("Authorization", "Bearer "+key)
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
	return detectorspb.DetectorType_Flutterwave
}

func (s scanner) Description() string {
	return "Detects Flutterwave API secret keys"
}