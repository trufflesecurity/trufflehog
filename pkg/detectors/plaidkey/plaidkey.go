package plaidkey

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b([a-z0-9]{30})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b([a-z0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"plaid"}
}

// FromData will find and optionally verify PlaidKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// find all the matching keys and ids in the data and make a unique maps for both.
	uniqueKeys, uniqueIds := make(map[string]struct{}), make(map[string]struct{})

	for _, foundKey := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		key := foundKey[1]
		if detectors.StringShannonEntropy(key) < 3 {
			continue
		}

		uniqueKeys[key] = struct{}{}
	}

	for _, foundId := range idPat.FindAllStringSubmatch(dataStr, -1) {
		id := foundId[1]
		if detectors.StringShannonEntropy(id) < 3 {
			continue
		}

		uniqueIds[id] = struct{}{}
	}

	for key := range uniqueKeys {
		for id := range uniqueIds {

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_PlaidKey,
				Raw:          []byte(key),
			}
			environments := []string{"sandbox", "production"}
			if verify {
				for _, env := range environments {
					isVerified, _, verificationErr := verifyMatch(ctx, client, id, key, env)
					s1.Verified = isVerified
					s1.ExtraData = map[string]string{"environment": fmt.Sprintf("https://%s.plaid.com", env)}
					s1.SetVerificationError(verificationErr, id, key)
				}
				results = append(results, s1)
				// if the environment is sandbox, we don't need to check production
				if s1.Verified {
					break
				}
			} else {
				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, id string, secret string, env string) (bool, map[string]string, error) {
	payload := strings.NewReader(`{"client_id":"` + id + `","secret":"` + secret + `","user":{"client_user_id":"60e3ee4019a2660010f8bc54","phone_number_verified_time":"0001-01-01T00:00:00Z","email_address_verified_time":"0001-01-01T00:00:00Z"},"client_name":"Plaid Test App","products":["auth","transactions"],"country_codes":["US"],"webhook":"https://webhook-uri.com","account_filters":{"depository":{"account_subtypes":["checking","savings"]}},"language":"en","link_customization_name":"default"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+env+".plaid.com/link/token/create", payload)
	if err != nil {
		return false, nil, nil
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil, nil
	case http.StatusBadRequest:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PlaidKey
}

func (s Scanner) Description() string {
	return "Plaid is a financial services company that provides a way to connect applications to users' bank accounts. Plaid API keys can be used to access and manage financial data."
}
