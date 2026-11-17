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

	// Values next to the word "plaid". The prefix window is 40 characters.
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b([a-f0-9]{30})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b([a-f0-9]{24})\b`)
	tokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b(access-(sandbox|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)

	// Labeled values. The engine only calls this detector when "plaid" is inside
	// the keyword span, so these do not repeat that 40-character window.
	// VCR cassettes put "plaid" in the request URL and the pair in the JSON body,
	// which is farther than 40 characters away.
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

	// A finding is the client id and secret. An access token is optional.
	uniqueSecrets := collectCandidates(dataStr, secretPat, labeledSecretPat)
	uniqueIds := collectCandidates(dataStr, idPat, labeledIDPat)
	uniqueTokens := collectCandidates(dataStr, tokenPat)

	if len(uniqueSecrets) == 0 || len(uniqueIds) == 0 {
		return
	}

	tokens := make([]string, 0, len(uniqueTokens))
	for token := range uniqueTokens {
		tokens = append(tokens, token)
	}
	if len(tokens) == 0 {
		// One pair result when the access token was not committed with the keys.
		tokens = append(tokens, "")
	}

	for secret := range uniqueSecrets {
		for id := range uniqueIds {
			for _, token := range tokens {
				rawV2 := fmt.Sprintf("%s:%s", secret, id)
				parts := map[string]string{
					"secret": secret,
					"id":     id,
				}
				if token != "" {
					rawV2 = fmt.Sprintf("%s:%s:%s", secret, id, token)
					parts["token"] = token
				}

				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_PlaidKey,
					Raw:          []byte(secret),
					RawV2:        []byte(rawV2),
					SecretParts:  parts,
				}

				if verify {
					if token != "" {
						environment := "sandbox"
						if strings.Contains(token, "production") {
							environment = "production"
						}
						isVerified, _, verificationErr := verifyMatch(ctx, client, id, secret, token, environment)
						s1.Verified = isVerified
						s1.ExtraData = map[string]string{"environment": fmt.Sprintf("https://%s.plaid.com", environment)}
						s1.SetVerificationError(verificationErr, id, secret)
					} else {
						isVerified, environment, verificationErr := verifyClientSecret(ctx, client, id, secret)
						s1.Verified = isVerified
						if isVerified {
							s1.ExtraData = map[string]string{"environment": fmt.Sprintf("https://%s.plaid.com", environment)}
						}
						s1.SetVerificationError(verificationErr, id, secret)
					}
				}
				results = append(results, s1)
			}
		}
	}

	return
}

// collectCandidates returns unique values from each pattern's first capture group.
func collectCandidates(data string, pats ...*regexp.Regexp) map[string]struct{} {
	found := make(map[string]struct{})
	for _, pat := range pats {
		for _, match := range pat.FindAllStringSubmatch(data, -1) {
			if len(match) < 2 {
				continue
			}
			value := match[1]
			if detectors.StringShannonEntropy(value) < 3 {
				continue
			}
			found[value] = struct{}{}
		}
	}
	return found
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

// verifyClientSecret checks a client id and secret that have no access token.
// The secret is different per environment, so both production and sandbox are tried.
// /institutions/get only needs the pair. https://plaid.com/docs/api/institutions/#institutionsget
func verifyClientSecret(ctx context.Context, client *http.Client, id string, secret string) (bool, string, error) {
	var lastErr error
	for _, env := range []string{"production", "sandbox"} {
		ok, err := verifyInstitutions(ctx, client, id, secret, env)
		if err != nil {
			lastErr = err
			continue
		}
		if ok {
			return true, env, nil
		}
	}
	return false, "", lastErr
}

func verifyInstitutions(ctx context.Context, client *http.Client, id string, secret string, env string) (bool, error) {
	payload := strings.NewReader(`{"client_id":"` + id + `","secret":"` + secret + `","count":1,"offset":0,"country_codes":["US"]}`)
	url := "https://" + env + ".plaid.com/institutions/get"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_PlaidKey
}

func (s Scanner) Description() string {
	return "Plaid is a financial services company that provides a way to connect applications to users' bank accounts. Plaid API keys can be used to access and manage financial data."
}
