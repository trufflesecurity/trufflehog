package tickettailor

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"tickettailor"}) + `\b(sk_[0-9]{4}_[0-9]{6}_[a-f0-9]{32})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"tickettailor"}
}

// FromData will find and optionally verify Tickettailor secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeyMatches := make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[match[1]] = struct{}{}
	}

	for key := range uniqueKeyMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Tickettailor,
			Raw:          []byte(key),
		}

		if verify {
			isVerified, verificationErr := verifyTicketTailor(ctx, client, key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Tickettailor
}

func (s Scanner) Description() string {
	return "Tickettailor is an online ticketing platform that allows event organizers to sell tickets. Tickettailor API keys can be used to manage events, orders, and tickets programmatically."
}

func verifyTicketTailor(ctx context.Context, client *http.Client, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.tickettailor.com/v1/orders", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Accept", "application/json")
	// as per API docs we only need to use apiKey as username in basic auth and leave password as empty: https://developers.tickettailor.com/#authentication
	req.SetBasicAuth(apiKey, "")
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
