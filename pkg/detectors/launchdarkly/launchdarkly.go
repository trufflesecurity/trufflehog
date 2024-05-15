package launchdarkly

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	ldclient "github.com/launchdarkly/go-server-sdk/v7"
	"github.com/launchdarkly/go-server-sdk/v7/ldcomponents"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient    = common.SaneHttpClient()
	defaultSDKConfig = ldclient.Config{
		Logging: ldcomponents.NoLogging(),
	}
	defaultSDKTimeout  = 10 * time.Second
	invalidSDKKeyError = "SDK key contains invalid characters"

	// Launchdarkly keys are UUIDv4s with either api- or sdk- prefixes.
	// mob- keys are possible, but are not sensitive credentials.
	keyPat = regexp.MustCompile(`\b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
)

type tokenResponse struct {
	Items      []token `json:"items"`
	TotalCount int32   `json:"totalCount"`
}

type token struct {
	Name           string `json:"name"`
	Role           string `json:"role"`
	Token          string `json:"token"`
	IsServiceToken bool   `json:"serviceToken"`
}

// We are not including "mob-" because client keys are not sensitive.
// They are expected to be public.
func (s Scanner) Keywords() []string {
	return []string{"api-", "sdk-"}
}

// FromData will find and optionally verify LaunchDarkly secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LaunchDarkly,
			Raw:          []byte(resMatch),
			ExtraData:    make(map[string]string),
		}

		if verify {
			if strings.HasPrefix(resMatch, "api-") {
				s1.ExtraData["type"] = "API"
				req, err := http.NewRequestWithContext(ctx, "GET", "https://app.launchdarkly.com/api/v2/tokens", nil)
				if err != nil {
					continue
				}
				client := s.client
				if client == nil {
					client = defaultClient
				}
				req.Header.Add("Authorization", resMatch)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
						var tokenResponse tokenResponse
						if err := json.NewDecoder(res.Body).Decode(&tokenResponse); err == nil && len(tokenResponse.Items) > 0 { // no error in parsing and have atleast one item
							// set first token information only
							token := tokenResponse.Items[0]
							s1.ExtraData["token_name"] = token.Name
							s1.ExtraData["token_role"] = token.Role
							s1.ExtraData["token_value"] = token.Token
							if token.IsServiceToken {
								s1.ExtraData["token_type"] = "service"
							} else {
								s1.ExtraData["token_type"] = "personal"
							}
							s1.ExtraData["total_token_count"] = fmt.Sprintf("%d", tokenResponse.TotalCount)
						}
					} else if res.StatusCode == 401 {
						// 401 is expected for an invalid token, so there is nothing to do here.
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, resMatch)
					}
				} else {
					s1.SetVerificationError(err, resMatch)
				}
			} else {
				// This is a server SDK key. Try to initialize using the SDK.
				s1.ExtraData["type"] = "SDK"
				_, err := ldclient.MakeCustomClient(resMatch, defaultSDKConfig, defaultSDKTimeout)
				if err == nil {
					s1.Verified = true
				} else if errors.Is(err, ldclient.ErrInitializationFailed) || err.Error() == invalidSDKKeyError {
					// If initialization fails, the key is not valid, so do nothing.
				} else {
					// If the error isn't nil or known, then this is likely a timeout error: ldclient.ErrInitializationTimeout
					// But any other error here means we don't know if this key is valid.
					s1.SetVerificationError(err, resMatch)
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LaunchDarkly
}
