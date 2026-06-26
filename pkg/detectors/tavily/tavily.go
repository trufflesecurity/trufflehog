package tavily

import (
	"context"
	"encoding/json"
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

	// Tavily API keys are prefixed with "tvly-" and may carry an optional
	// environment tier ("dev-" or "prod-") before the random body.
	keyPat = regexp.MustCompile(`\b(tvly-(?:dev-|prod-)?[A-Za-z0-9]{20,40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"tvly-"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Tavily secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Tavily,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			verified, extraData, verificationErr := verifyToken(ctx, s.getClient(), token)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, token)
		}

		results = append(results, s1)
	}

	return
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.tavily.com/usage", http.NoBody)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

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
		var resData usageResponse
		if err = json.NewDecoder(res.Body).Decode(&resData); err != nil {
			// The key is valid even if the response body is unexpected.
			return true, nil, nil
		}

		extraData := map[string]string{
			"current_plan": resData.Account.CurrentPlan,
			"plan_usage":   fmt.Sprintf("%d", resData.Account.PlanUsage),
			"plan_limit":   fmt.Sprintf("%d", resData.Account.PlanLimit),
			"key_usage":    fmt.Sprintf("%d", resData.Key.Usage),
		}
		return true, extraData, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Invalid or revoked key.
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Tavily
}

func (s Scanner) Description() string {
	return "Tavily is a web search and data retrieval API built for AI agents and RAG applications. Tavily API keys can be used to perform searches and access account usage and billing resources."
}

type usageResponse struct {
	Key struct {
		Usage int `json:"usage"`
	} `json:"key"`
	Account struct {
		CurrentPlan string `json:"current_plan"`
		PlanUsage   int    `json:"plan_usage"`
		PlanLimit   int    `json:"plan_limit"`
	} `json:"account"`
}
