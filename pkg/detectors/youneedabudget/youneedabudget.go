package youneedabudget

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// YNAB Personal Access Tokens are 64-character hexadecimal strings
	// Based on documentation: access tokens are used with Bearer authentication
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"youneedabudget", "ynab"}) + `([A-Za-z0-9_-]{43,44})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"youneedabudget", "ynab"}
}

// FromData will find and optionally verify YouNeedABudget secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_YouNeedABudget,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, err := verifyMatch(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(err, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Reference: https://api.youneedabudget.com/#authentication-overview
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.youneedabudget.com/v1/user", http.NoBody)
	if err != nil {
		return false, err
	}

	// YNAB API requires Bearer authentication in Authorization header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_YouNeedABudget
}

func (s Scanner) Description() string {
	return "YouNeedABudget is a budgeting tool that allows users to manage their personal finances. The API keys can be used to access and modify a user's financial data."
}
