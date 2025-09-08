package opsgenie

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"opsgenie"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Opsgenie
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"opsgenie"}
}

// Description returns a description for the result being detected
func (s Scanner) Description() string {
	return "Opsgenie is an alerting and incident management platform. Opsgenie API keys can be used to interact with the Opsgenie API to manage alerts and incidents."
}

// FromData will find and optionally verify Opsgenie secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		if strings.Contains(match[0], "opsgenie.com/alert/detail/") {
			continue
		}

		k := match[1]
		if detectors.StringShannonEntropy(k) < 3 {
			continue
		}
		keyMatches[k] = struct{}{}
	}

	for key := range keyMatches {
		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_Opsgenie,
			Raw:          []byte(key),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, vErr := verifyMatch(ctx, client, key)
			if isVerified {
				r.Verified = isVerified
				r.ExtraData = extraData
				r.AnalysisInfo = map[string]string{
					"key": key,
				}
			}
			r.SetVerificationError(vErr, key)
		}

		results = append(results, r)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, key string) (bool, map[string]string, error) {
	// https://docs.opsgenie.com/docs/account-api
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.opsgenie.com/v2/account", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("GenieKey %s", key))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var accountRes accountResponse
		if err := json.NewDecoder(res.Body).Decode(&accountRes); err != nil {
			return false, nil, err
		}

		extraData := map[string]string{
			"account": accountRes.Data.Name,
			"plan":    accountRes.Data.Plan.Name,
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		// Key is not valid
		return false, nil, nil
	case http.StatusForbidden:
		// Key is valid but lacks permissions
		return true, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

type accountResponse struct {
	Data struct {
		Name      string `json:"name"`
		UserCount int    `json:"userCount"`
		Plan      struct {
			Name string `json:"name"`
		} `json:"plan"`
	} `json:"data"`
}
