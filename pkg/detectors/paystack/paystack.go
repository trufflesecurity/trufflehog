package paystack

import (
	"bytes"
	"context"
	"io"
	"net/http"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var (
	paystackKeyPattern = regexp.MustCompile(`sk_[a-z]{1,}_[0-9a-zA-Z]{40}`)
	paystackClient     = common.SaneHttpClient()
)

type scanner struct{}

var _ detectors.Detector = (*scanner)(nil)

func (s scanner) Keywords() []string {
	return []string{"paystack", "sk_live", "sk_test"}
}

func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := paystackKeyPattern.FindAllString(dataStr, -1)

	for _, match := range matches {
		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Paystack,
			Raw:          []byte(match),
		}

		if verify {
			isVerified := verifyPaystackKey(ctx, match)
			s.Verified = isVerified
		}

		results = append(results, s)
	}

	return results, nil
}

func verifyPaystackKey(ctx context.Context, key string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.paystack.co/balance", nil)
	if err != nil {
		return false
	}

	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Content-Type", "application/json")

	resp, err := paystackClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// Invalid responses
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}

	// Valid response: 2xx without "invalid"/"unauthorized" keywords
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if !bytes.Contains(bodyBytes, []byte("invalid")) && !bytes.Contains(bodyBytes, []byte("unauthorized")) {
			return true
		}
		return false
	}

	return false
}

func (s scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Paystack
}

func (s scanner) Description() string {
	return "Detects Paystack API secret keys (sk_* format)"
}