package twilioapikey

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
	_ detectors.CloudProvider      = (*Scanner)(nil)
)

func (Scanner) CloudEndpoint() string { return "https://verify.twilio.com" }

var (
	defaultClient = detectors.NewClientWithDedup(common.SaneHttpClient())
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
	return s.VerificationClient(cmp.Or(s.client, defaultClient))
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"twilio"}
}

// FromData will find and optionally verify Twilio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueAPIKeys := make(map[string]struct{})
	for _, k := range apiKeyPat.FindAllString(dataStr, -1) {
		uniqueAPIKeys[k] = struct{}{}
	}
	uniqueSecrets := make(map[string]struct{})
	for _, sec := range secretPat.FindAllString(dataStr, -1) {
		uniqueSecrets[sec] = struct{}{}
	}

	endpoints := s.Endpoints()
	if len(endpoints) == 0 {
		endpoints = []string{s.CloudEndpoint()}
	}

	for apiKey := range uniqueAPIKeys {
		for secret := range uniqueSecrets {
			s1 := detectors.Result{
				DetectorType: s.Type(),
				Raw:          []byte(apiKey),
				RawV2:        []byte(apiKey + secret),
				Redacted:     secret[:5] + "...",
				ExtraData:    make(map[string]string),
				SecretParts:  map[string]string{"key": apiKey, "secret": secret},
			}

			if verify {
				client := s.getClient()
				var lastErr error
				for _, baseURL := range endpoints {
					extraData, isVerified, verificationErr := verifyTwilioAPIKey(ctx, client, apiKey, secret, baseURL)
					s1.Verified = isVerified
					if verificationErr != nil {
						lastErr = verificationErr
					}
					maps.Copy(s1.ExtraData, extraData)
					if isVerified {
						lastErr = nil
						break
					}
				}
				s1.SetVerificationError(lastErr, secret)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_TwilioApiKey
}

func (s Scanner) Description() string {
	return "Twilio is a cloud communications platform that allows software developers to programmatically make and receive phone calls, send and receive text messages, and perform other communication functions using its web service APIs."
}

func verifyTwilioAPIKey(ctx context.Context, client *http.Client, apiKey, secret, baseURL string) (map[string]string, bool, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	reqURL := fmt.Sprintf("%s/v2/Services", baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, false, err
	}

	req.Header.Add("Accept", "application/json")
	req.SetBasicAuth(apiKey, secret)

	resp, err := detectors.DoWithDedup(client, detector_typepb.DetectorType_TwilioApiKey, apiKey+secret+baseURL, req)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		extraData := make(map[string]string)
		var serviceResponse serviceResponse

		if err := json.NewDecoder(resp.Body).Decode(&serviceResponse); err == nil && len(serviceResponse.Services) > 0 {
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
