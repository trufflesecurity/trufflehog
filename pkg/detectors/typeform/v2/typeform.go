package typeform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\btfp_[a-zA-Z0-9_]{40,59}\b`)
)

func (s Scanner) Version() int { return 2 }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"tfp_"}
}

type TypeFormResponse struct {
	UserID   string `json:"user_id,omitempty"`
	Email    string `json:"email,omitempty"`
	Alias    string `json:"alias,omitempty"`
	Language string `json:"language,omitempty"`
}

// FromData will find and optionally verify Typeform secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllString(dataStr, -1)

	for _, match := range matches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Typeform,
			Raw:          []byte(match),
		}

		if verify {
			verified, typeformResponse, requestErr := verifyMatch(ctx, client, match)
			s1.Verified = verified
			if requestErr != nil {
				s1.SetVerificationError(err, match)
			} else {
				s1.ExtraData = map[string]string{
					"UserId":   typeformResponse.UserID,
					"Email":    typeformResponse.Email,
					"Alias":    typeformResponse.Alias,
					"Language": typeformResponse.Language,
				}
			}
		}
		results = append(results, s1)

	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, secret string) (bool, TypeFormResponse, error) {
	var response TypeFormResponse

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.typeform.com/me", nil)
	if err != nil {
		return false, response, nil
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", secret))
	res, err := client.Do(req)
	if err != nil {
		return false, response, err
	}
	defer res.Body.Close()
	if err = json.NewDecoder(res.Body).Decode(&response); err != nil {
		return false, response, err
	}
	if res.StatusCode == 200 {
		return true, response, nil
	} else {
		return false, response, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Typeform
}

func (s Scanner) Description() string {
	return "Typeform is a service for creating forms and surveys. Typeform API keys can be used to access and manage forms and responses."
}
