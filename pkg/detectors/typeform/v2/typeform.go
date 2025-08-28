package typeform

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
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\btfp_[a-zA-Z0-9_]{40,59}\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return client
}

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
			verified, typeformResponse, requestErr := verifyMatch(ctx, s.getClient(), match)
			s1.Verified = verified
			s1.SetVerificationError(requestErr)

			if typeformResponse != nil {
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

func verifyMatch(ctx context.Context, client *http.Client, secret string) (bool, *TypeFormResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.typeform.com/me", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", secret))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode == 200 {
		var response *TypeFormResponse
		if err = json.NewDecoder(res.Body).Decode(&response); err != nil {
			return false, nil, err
		}

		return true, response, nil
	} else if res.StatusCode == 401 || res.StatusCode == 403 {
		return false, nil, nil
	} else {
		return false, nil, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Typeform
}

func (s Scanner) Description() string {
	return "Typeform is a service for creating forms and surveys. Typeform API keys can be used to access and manage forms and responses."
}
