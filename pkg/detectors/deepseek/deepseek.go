package deepseek

import (
	"context"
	"encoding/json"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\b(sk-[a-z0-9]{32})+\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sk-"}
}

// FromData will find and optionally verify DeepSeek secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DeepSeek,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			verified, extraData, verificationErr := verifyToken(ctx, client, token)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.deepseek.com/user/balance", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case 200:
		var resData response
		if err = json.NewDecoder(res.Body).Decode(&resData); err != nil {
			return false, nil, err
		}

		extraData := map[string]string{
			"is available": fmt.Sprintf("%t", resData.IsAvailable),
		}
		if len(resData.BalanceInfos) > 0 {
			extraData["currency"] = resData.BalanceInfos[0].Currency
			extraData["total balance"] = resData.BalanceInfos[0].TotalBalance
			extraData["granted balance"] = resData.BalanceInfos[0].GrantedBalance
			extraData["topped up balance"] = resData.BalanceInfos[0].ToppedUpBalance
		}
		return true, extraData, nil
	case 401:
		// Invalid
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DeepSeek
}

func (s Scanner) Description() string {
	return "DeepSeek is an artificial intelligence company that develops large language models (LLMs)"
}

type response struct {
	IsAvailable  bool           `json:"is_available"`
	BalanceInfos []responseInfo `json:"balance_infos"`
}
type responseInfo struct {
	Currency        string `json:"currency"`
	TotalBalance    string `json:"total_balance"`
	GrantedBalance  string `json:"granted_balance"`
	ToppedUpBalance string `json:"topped_up_balance"`
}
