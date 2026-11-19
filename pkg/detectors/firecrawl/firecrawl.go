package firecrawl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

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

const (
	creditUsageURL = "https://api.firecrawl.dev/v2/team/credit-usage"
	maxBody        = 1 << 16
)

var (
	defaultClient = common.SaneHttpClient()

	// Firecrawl API keys are fc- followed by a UUID with its dashes removed.
	// https://github.com/firecrawl/firecrawl/blob/main/apps/api/src/lib/parseApi.ts
	keyPat = regexp.MustCompile(`\b(fc-[a-f0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"fc-"}
}

// FromData will find and optionally verify Firecrawl API keys in a given set of bytes.
// Legacy keys without the fc- prefix are bare UUIDs and are not detected.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Firecrawl,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
			if len(extraData) > 0 {
				s1.ExtraData = extraData
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, key string) (bool, map[string]string, error) {
	// GET /team/credit-usage returns the remaining credits for the key's team
	// and does not spend any credits.
	// https://docs.firecrawl.dev/api-reference/endpoint/credit-usage
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, creditUsageURL, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Accept", "application/json")

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
		// Determinate success: key is live. Capture credit fields when present.
		extra := map[string]string{}
		body, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
		if err != nil {
			return true, extra, nil
		}
		var payload struct {
			Data struct {
				RemainingCredits *float64 `json:"remainingCredits"`
				PlanCredits      *float64 `json:"planCredits"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &payload) == nil {
			if payload.Data.RemainingCredits != nil {
				extra["remaining_credits"] = strconv.FormatFloat(*payload.Data.RemainingCredits, 'f', -1, 64)
			}
			if payload.Data.PlanCredits != nil {
				extra["plan_credits"] = strconv.FormatFloat(*payload.Data.PlanCredits, 'f', -1, 64)
			}
		}
		return true, extra, nil
	case http.StatusUnauthorized:
		// Determinate failure: key is invalid or revoked.
		return false, nil, nil
	default:
		// Indeterminate: unexpected status (rate limit, 5xx, etc).
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Firecrawl
}

func (s Scanner) Description() string {
	return "Firecrawl is a web scraping and crawling API for LLM applications. API keys authenticate scrape, crawl, search, and extract requests and spend the team's credits."
}
