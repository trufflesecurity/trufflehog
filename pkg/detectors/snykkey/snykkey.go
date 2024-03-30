package snykkey

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

var keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"snyk"}) + `\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"snyk"}
}

// FromData will find and optionally verify SnykKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		tokens[match[1]] = struct{}{}
	}

	for token := range tokens {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
		}

		if verify {
			isVerified, extraData, verificationErr := s.doVerification(ctx, token)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, token)
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) doVerification(ctx context.Context, token string) (bool, map[string]string, error) {
	client := s.client
	if client == nil {
		client = common.SaneHttpClient()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://snyk.io/api/v1/user/me", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()
	if res.StatusCode == http.StatusOK {
		userDetails := userDetailsResponse{}
		err := json.NewDecoder(res.Body).Decode(&userDetails)
		if err != nil {
			return true, nil, err
		} else if userDetails.Username == "" {
			return false, nil, fmt.Errorf("failed to decode JSON response")
		}

		extraData := map[string]string{
			"Username": userDetails.Username,
			"Email":    userDetails.Email,
		}

		// Condense a list of organizations
		if len(userDetails.Organizations) > 0 {
			var orgs []string
			for _, org := range userDetails.Organizations {
				orgs = append(orgs, org.Name)
			}
			extraData["Organizations"] = strings.Join(orgs, ",")
		}
		return true, extraData, nil
	} else if res.StatusCode == http.StatusUnauthorized {
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	} else {
		err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, nil, err
	}
}

// https://snyk.docs.apiary.io/#reference/users/my-user-details/get-my-details
type userDetailsResponse struct {
	Username      string         `json:"username"`
	Email         string         `json:"email"`
	Organizations []organization `json:"orgs"`
}

type organization struct {
	Name string `json:"name"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SnykKey
}
