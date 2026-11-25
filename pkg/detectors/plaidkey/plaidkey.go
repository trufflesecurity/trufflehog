package plaidkey

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
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

	// Labeled values. This detector runs only when "plaid" is inside the 1024-byte
	// keyword span, so these do not repeat the 40-character prefix. In request
	// bodies the label is a few characters from the hex, while "plaid" is farther away.
	labeledSecretPat = regexp.MustCompile(`(?i)\bsecret\b[^a-f0-9]{0,20}([a-f0-9]{30})\b`)
	labeledIDPat     = regexp.MustCompile(`(?i)\bclient_id\b[^a-f0-9]{0,20}([a-f0-9]{24})\b`)
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

	collectMatches(uniqueSecrets, dataStr, secretPat, labeledSecretPat)
	collectMatches(uniqueIds, dataStr, idPat, labeledIDPat)
	collectMatches(uniqueTokens, dataStr, tokenPat)

	for secret := range uniqueSecrets {
		for id := range uniqueIds {
			for token := range uniqueTokens {
				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_PlaidKey,
					Raw:          []byte(secret),
					RawV2:        []byte(fmt.Sprintf(`%s:%s:%s`, secret, id, token)),
					SecretParts: map[string]string{
						"secret": secret,
						"id":     id,
						"token":  token,
					},
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
				}
				results = append(results, s1)
			}

			// No access token was found. Report the client id and secret on their own.
			// /item/get needs the token, so this result is not verified.
			if len(uniqueTokens) == 0 {
				results = append(results, detectors.Result{
					DetectorType: detector_typepb.DetectorType_PlaidKey,
					Raw:          []byte(secret),
					RawV2:        []byte(fmt.Sprintf("%s:%s", secret, id)),
					SecretParts: map[string]string{
						"secret": secret,
						"id":     id,
					},
				})
			}
		}
	}

	return
}

func collectMatches(dst map[string]struct{}, data string, pats ...*regexp.Regexp) {
	for _, pat := range pats {
		for _, match := range pat.FindAllStringSubmatch(data, -1) {
			if len(match) < 2 {
				continue
			}
			value := match[1]
			if detectors.StringShannonEntropy(value) < 3 {
				continue
			}
			dst[value] = struct{}{}
		}
	}
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
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil, nil
	case http.StatusBadRequest:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_PlaidKey
}

func (s Scanner) Description() string {
	return "Plaid is a financial services company that provides a way to connect applications to users' bank accounts. Plaid API keys can be used to access and manage financial data."
}
