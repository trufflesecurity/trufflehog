package twilioapikey

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
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	apiKeyPat     = regexp.MustCompile(`\bSK[a-zA-Z0-9]{32}\b`)
	secretPat     = regexp.MustCompile(`\b[0-9a-zA-Z]{32}\b`)
)

type serviceResponse struct {
	Services []struct {
		FriendlyName string `json:"friendly_name"` // friendly name of a service
		SID          string `json:"sid"`           // object id of service
		AccountSID   string `json:"account_sid"`   // account sid
	} `json:"services"`
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"twilio"}
}

// FromData will find and optionally verify Twilio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiKeyMatches := apiKeyPat.FindAllString(dataStr, -1)
	secretMatches := secretPat.FindAllString(dataStr, -1)

	for _, apiKey := range apiKeyMatches {
		for _, secret := range secretMatches {
			s1 := detectors.Result{
				// TODO: We need to use the correct DetectorType here; detectorspb.DetectorType_TwilioApiKey
				DetectorType: detectorspb.DetectorType_Twilio,
				Raw:          []byte(apiKey),
				RawV2:        []byte(apiKey + secret),
				Redacted:     secret[:5] + "...",
				ExtraData:    make(map[string]string),
			}

			if verify {
				extraData, isVerified, verificationErr := verifyTwilioAPIKey(ctx, s.getClient(), apiKey, secret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)

				for key, value := range extraData {
					s1.ExtraData[key] = value
				}

				if s1.Verified {
					s1.AnalysisInfo = map[string]string{"key": apiKey, "sid": secret}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TwilioApiKey
}

func (s Scanner) Description() string {
	return "Twilio is a cloud communications platform that allows software developers to programmatically make and receive phone calls, send and receive text messages, and perform other communication functions using its web service APIs."
}

func verifyTwilioAPIKey(ctx context.Context, client *http.Client, apiKey, secret string) (map[string]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://verify.twilio.com/v2/Services", nil)
	if err != nil {
		return nil, false, nil
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "*/*")
	req.SetBasicAuth(apiKey, secret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		extraData := make(map[string]string)
		var serviceResponse serviceResponse

		if err := json.NewDecoder(resp.Body).Decode(&serviceResponse); err == nil && len(serviceResponse.Services) > 0 { // no error in parsing and have at least one service
			service := serviceResponse.Services[0]
			extraData["friendly_name"] = service.FriendlyName
			extraData["account_sid"] = service.AccountSID
		}

		return extraData, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
