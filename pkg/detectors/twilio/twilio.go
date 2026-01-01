package twilio

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
	sidPat        = regexp.MustCompile(`\bAC[0-9a-f]{32}\b`)
	keyPat        = regexp.MustCompile(`\b[0-9a-f]{32}\b`)
)

type serviceResponse struct {
	Services []service `json:"services"`
}

type service struct {
	FriendlyName string `json:"friendly_name"` // friendly name of a service
	SID          string `json:"sid"`           // object id of service
	AccountSID   string `json:"account_sid"`   // account sid
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
	return []string{"sid", "twilio"}
}

// FromData will find and optionally verify Twilio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllString(dataStr, -1)
	sidMatches := sidPat.FindAllString(dataStr, -1)

	for _, sid := range sidMatches {
		for _, key := range keyMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Twilio,
				Raw:          []byte(sid),
				RawV2:        []byte(sid + ":" +  key),
				Redacted:     sid,
			}

			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/twilio/",
			}

			if verify {
				extraData, isVerified, verificationErr := verifyTwilio(ctx, s.getClient(), key, sid)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)

				for key, value := range extraData {
					s1.ExtraData[key] = value
				}

				if s1.Verified {
					s1.AnalysisInfo = map[string]string{"key": key, "sid": sid}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Twilio
}

func (s Scanner) Description() string {
	return "Twilio is a cloud communications platform that allows software developers to programmatically make and receive phone calls, send and receive text messages, and perform other communication functions using its web service APIs."
}

func verifyTwilio(ctx context.Context, client *http.Client, key, sid string) (map[string]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://verify.twilio.com/v2/Services", nil)
	if err != nil {
		return nil, false, nil
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "*/*")
	req.SetBasicAuth(sid, key)
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
