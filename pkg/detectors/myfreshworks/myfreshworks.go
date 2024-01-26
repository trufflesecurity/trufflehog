package myfreshworks

import (
	"context"
	"encoding/json"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"net/http"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"freshworks"}) + `\b([a-z0-9A-Z-_]{22})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"freshworks"}) + `\b([a-zA-Z0-9-_]{2,20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"freshworks"}
}

// FromData will find and optionally verify Myfreshworks secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, idmatch := range idmatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Myfreshworks,
				Raw:          []byte(resMatch),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyMyfreshworks(ctx, client, resMatch, resIdMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}
			results = append(results, s1)
		}

	}

	return results, nil
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func verifyMyfreshworks(ctx context.Context, client *http.Client, resMatch, resIdMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+resIdMatch+".myfreshworks.com/crm/sales/api/sales_accounts/filters", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Token token=%s", resMatch))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}

		return json.Valid(body), nil
	} else if !(res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden) {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Myfreshworks
}
