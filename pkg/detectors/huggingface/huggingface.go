package huggingface

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
	keyPat = regexp.MustCompile(`\bhf_[a-zA-Z0-9]{34}\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"huggingface", "hugging_face", "hf"} // Huggingface docs occasionally use "hf" instead of "huggingface"
}

// FromData will find and optionally verify Huggingface secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 1 {
			continue
		}
		resMatch := strings.TrimSpace(match[0])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_HuggingFace,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, extraData, verificationErr := s.verifyResult(ctx, resMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, resMatch)
		}

		// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) verifyResult(ctx context.Context, apiKey string) (bool, map[string]string, error) {
	client := s.client
	if client == nil {
		client = defaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://huggingface.co/api/whoami-v2", nil)
	if err != nil {
		return false, nil, nil
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}

	defer res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		whoamiRes := whoamiResponse{}
		err := json.NewDecoder(res.Body).Decode(&whoamiRes)
		if err != nil {
			return true, nil, err
		}

		t := whoamiRes.Auth.AccessToken
		extraData := map[string]string{
			"Username": whoamiRes.Name,
			"Email":    whoamiRes.Email,
			"Token":    fmt.Sprintf("%s (%s)", t.DisplayName, t.Role),
		}

		// Condense a list of organizations + roles.
		var orgs []string
		for _, org := range whoamiRes.Organizations {
			orgs = append(orgs, fmt.Sprintf("%s:%s", org.Name, org.Role))
		}
		if len(orgs) > 0 {
			extraData["Organizations"] = strings.Join(orgs, ", ")
		}
		return true, extraData, nil
	} else if res.StatusCode == 401 {
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	} else {
		err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, nil, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_HuggingFace
}

// https://huggingface.co/docs/hub/api#get-apiwhoami-v2
type whoamiResponse struct {
	Name          string         `json:"name"`
	Email         string         `json:"email"`
	Organizations []organization `json:"orgs"`
	Auth          auth           `json:"auth"`
}

type organization struct {
	Name string `json:"name"`
	Role string `json:"roleInOrg"`
}

type auth struct {
	AccessToken struct {
		DisplayName string `json:"displayName"`
		Role        string `json:"role"`
	} `json:"accessToken"`
}
