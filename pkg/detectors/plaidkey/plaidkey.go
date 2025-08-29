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
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b([a-f0-9]{30})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b([a-f0-9]{24})\b`)
	tokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b(access-(sandbox|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)
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
	uniqueSecrets, uniqueIds, uniqueTokens := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})

	for _, foundKey := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		key := foundKey[1]
		if detectors.StringShannonEntropy(key) < 3 {
			continue
		}

		uniqueSecrets[key] = struct{}{}
	}

	for _, foundId := range idPat.FindAllStringSubmatch(dataStr, -1) {
		id := foundId[1]
		if detectors.StringShannonEntropy(id) < 3 {
			continue
		}

		uniqueIds[id] = struct{}{}
	}

	for _, foundToken := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		token := foundToken[1]
		if detectors.StringShannonEntropy(token) < 3 {
			continue
		}

		uniqueTokens[token] = struct{}{}
	}

	for secret := range uniqueSecrets {
		for id := range uniqueIds {
			for token := range uniqueTokens {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_PlaidKey,
					Raw:          []byte(secret),
					RawV2:        []byte(fmt.Sprintf(`%s:%s:%s`, secret, id, token)),
				}

				if verify {
					environment := "sandbox"
					if strings.Contains(token, "production") {
						environment = "production"
					}
					isVerified, _, verificationErr := verifyMatch(ctx, client, id, secret, token, environment)
					s1.Verified = isVerified
					s1.ExtraData = map[string]string{"environment": fmt.Sprintf("https://%s.plaid.com", environment)}
					s1.SetVerificationError(verificationErr, id, secret)
					if s1.Verified {
						s1.AnalysisInfo = map[string]string{
							"secret": secret,
							"id":     id,
							"token":  token,
						}
					}
				}
				results = append(results, s1)
			}
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, id string, secret string, token string, env string) (bool, map[string]string, error) {
	payload := strings.NewReader(`{"client_id":"` + id + `","secret":"` + secret + `","access_token":"` + token + `"}`)
	url := "https://" + env + ".plaid.com/item/get"
	req, err := http.NewRequestWithContext(ctx, "POST", url, payload)
	if err != nil {
		return false, nil, err
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
