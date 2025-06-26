package eventbrite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"eventbrite"}) + `\b([0-9A-Z]{20})\b`)
)

func (s *Scanner) getClient() *http.Client {
	if s.client == nil {
		return defaultClient
	}

	return s.client
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"eventbrite"}
}

// FromData will find and optionally verify Eventbrite secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokenMatches := make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokenMatches[match[1]] = struct{}{}
	}

	for token := range uniqueTokenMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Eventbrite,
			Raw:          []byte(token),
			ExtraData:    map[string]string{},
		}

		if verify {
			extraData, isVerified, verificationErr := verifyEventBrite(ctx, s.getClient(), token)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
			s1.ExtraData = extraData
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Eventbrite
}

func (s Scanner) Description() string {
	return "Eventbrite is an event management and ticketing website. Eventbrite API keys can be used to access and manage event data."
}

func verifyEventBrite(ctx context.Context, client *http.Client, token string) (map[string]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.eventbriteapi.com/v3/users/me/?token="+token, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var response map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return nil, false, err
		}

		userName := response["name"].(string)

		return map[string]string{"user name": userName}, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
