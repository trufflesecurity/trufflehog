package twilio

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

func (Scanner) CloudEndpoint() string { return "https://api.twilio.com" }

var (
	defaultClient = detectors.NewClientWithDedup(common.RetryableHTTPClient())
	sidPat        = regexp.MustCompile(`\bAC[0-9a-f]{32}\b`)
	keyPat        = regexp.MustCompile(`\b[0-9a-f]{32}\b`)
)

type accountResponse struct {
	SID             string `json:"sid"`
	OwnerAccountSID string `json:"owner_account_sid"`
	FriendlyName    string `json:"friendly_name"`
	Status          string `json:"status"`
	Type            string `json:"type"`
}

func (s Scanner) getClient() *http.Client {
	return s.VerificationClient(cmp.Or(s.client, defaultClient))
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sid", "twilio"}
}

// FromData will find and optionally verify Twilio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, k := range keyPat.FindAllString(dataStr, -1) {
		uniqueKeys[k] = struct{}{}
	}
	uniqueSIDs := make(map[string]struct{})
	for _, s := range sidPat.FindAllString(dataStr, -1) {
		uniqueSIDs[s] = struct{}{}
	}

	endpoints := s.Endpoints()
	if len(endpoints) == 0 {
		endpoints = []string{s.CloudEndpoint()}
	}

	for sid := range uniqueSIDs {
		for key := range uniqueKeys {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Twilio,
				Raw:          []byte(sid),
				RawV2:        []byte(sid + key),
				Redacted:     sid,
				SecretParts:  map[string]string{"key": key, "sid": sid},
			}

			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/twilio/",
			}

			if verify {
				client := s.getClient()
				var lastErr error
				for _, baseURL := range endpoints {
					extraData, isVerified, verificationErr := verifyTwilio(ctx, client, key, sid, baseURL)
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
				s1.SetVerificationError(lastErr, key)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Twilio
}

func (s Scanner) Description() string {
	return "Twilio is a cloud communications platform that allows software developers to programmatically make and receive phone calls, send and receive text messages, and perform other communication functions using its web service APIs."
}

func verifyTwilio(ctx context.Context, client *http.Client, key, sid, baseURL string) (map[string]string, bool, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	reqURL := fmt.Sprintf("%s/2010-04-01/Accounts/%s.json", baseURL, sid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, false, err
	}

	req.Header.Add("Accept", "application/json")
	req.SetBasicAuth(sid, key)
	resp, err := detectors.DoWithDedup(client, detector_typepb.DetectorType_Twilio, sid+key+baseURL, req)
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
		var account accountResponse

		if err := json.NewDecoder(resp.Body).Decode(&account); err == nil {
			if account.SID != "" {
				extraData["account_sid"] = account.SID
			} else {
				extraData["account_sid"] = sid
			}
			if account.FriendlyName != "" {
				extraData["friendly_name"] = account.FriendlyName
			}
			if account.Status != "" {
				extraData["status"] = account.Status
			}
			if account.Type != "" {
				extraData["type"] = account.Type
			}
			if account.OwnerAccountSID != "" && account.OwnerAccountSID != account.SID {
				extraData["owner_account_sid"] = account.OwnerAccountSID
				extraData["is_subaccount"] = "true"
			}
		}

		return extraData, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
