package twilioapikey

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
	client                *http.Client
	cloudEndpointDisabled bool
}

// Ensure the Scanner satisfies the interface at compile time.
var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
	_ detectors.CloudProvider      = (*Scanner)(nil)
)

func (s *Scanner) UseCloudEndpoint(enabled bool) {
	s.EndpointSetter.UseCloudEndpoint(enabled)
	s.cloudEndpointDisabled = !enabled
}

func (Scanner) CloudEndpoint() string { return "https://verify.twilio.com/v2/Services" }

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
	if len(endpoints) == 0 && !s.cloudEndpointDisabled {
		endpoints = []string{s.CloudEndpoint()}
	}

	var client *http.Client
	if verify && len(endpoints) > 0 {
		client = s.getClient()
		for _, endpointURL := range endpoints {
			if u, err := url.Parse(endpointURL); err == nil && strings.TrimRight(u.Path, "/") == "" {
				logger := logContext.AddLogger(ctx).Logger().WithName("twilioapikey")
				logger.Info(fmt.Sprintf("warning: custom verifier endpoint %s is missing a path portion; validating against root", u.Redacted()))
			}
		}
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

			if verify && client != nil {
				var lastErr error
				for _, endpointURL := range endpoints {
					extraData, isVerified, verificationErr := verifyTwilioAPIKey(ctx, client, apiKey, secret, endpointURL)
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

func verifyTwilioAPIKey(ctx context.Context, client *http.Client, apiKey, secret, endpointURL string) (map[string]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return nil, false, err
	}

	req.Header.Add("Accept", "application/json")
	req.SetBasicAuth(apiKey, secret)

	resp, err := detectors.DoWithDedup(client, detector_typepb.DetectorType_TwilioApiKey, apiKey+secret+endpointURL, req)
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
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, false, err
		}

		var hasTwilioPayload bool

		// Try decoding as Verify API /v2/Services response
		var serviceResponse struct {
			Services *[]struct {
				FriendlyName string `json:"friendly_name"`
				SID          string `json:"sid"`
				AccountSID   string `json:"account_sid"`
			} `json:"services"`
		}
		if err := json.Unmarshal(bodyBytes, &serviceResponse); err == nil && serviceResponse.Services != nil {
			hasTwilioPayload = true
			if len(*serviceResponse.Services) > 0 {
				service := (*serviceResponse.Services)[0]
				if service.FriendlyName != "" {
					extraData["friendly_name"] = service.FriendlyName
				}
				if service.AccountSID != "" {
					extraData["account_sid"] = service.AccountSID
				}
			}
		}

		// Try decoding as Core REST API Accounts list response (e.g. Accounts.json)
		if !hasTwilioPayload {
			var accountsList struct {
				Accounts *[]struct {
					SID          string `json:"sid"`
					FriendlyName string `json:"friendly_name"`
					Status       string `json:"status"`
					Type         string `json:"type"`
				} `json:"accounts"`
			}
			if err := json.Unmarshal(bodyBytes, &accountsList); err == nil && accountsList.Accounts != nil {
				hasTwilioPayload = true
				if len(*accountsList.Accounts) > 0 {
					acc := (*accountsList.Accounts)[0]
					if acc.SID != "" {
						extraData["account_sid"] = acc.SID
					}
					if acc.FriendlyName != "" {
						extraData["friendly_name"] = acc.FriendlyName
					}
					if acc.Status != "" {
						extraData["status"] = acc.Status
					}
					if acc.Type != "" {
						extraData["type"] = acc.Type
					}
				}
			}
		}

		// Try decoding as single account response
		if !hasTwilioPayload {
			var singleAcc struct {
				SID          string `json:"sid"`
				FriendlyName string `json:"friendly_name"`
				Status       string `json:"status"`
				Type         string `json:"type"`
			}
			if err := json.Unmarshal(bodyBytes, &singleAcc); err == nil && strings.HasPrefix(singleAcc.SID, "AC") {
				hasTwilioPayload = true
				extraData["account_sid"] = singleAcc.SID
				if singleAcc.FriendlyName != "" {
					extraData["friendly_name"] = singleAcc.FriendlyName
				}
				if singleAcc.Status != "" {
					extraData["status"] = singleAcc.Status
				}
				if singleAcc.Type != "" {
					extraData["type"] = singleAcc.Type
				}
			}
		}

		// Require a confirmed Twilio service or account structure to verify the credential.
		// This prevents generic 200 OK responses (e.g. health check endpoints or auth proxy portals)
		// from falsely validating arbitrary candidate credentials.
		if !hasTwilioPayload {
			return nil, false, fmt.Errorf("unexpected response payload from verifier endpoint")
		}

		if strings.EqualFold(extraData["status"], "closed") {
			return extraData, false, nil
		}

		return extraData, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
