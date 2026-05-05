package shopify

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
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Covers: shpca_, shpat_, shptka_, shppa_ (custom app, private app, token app, partner app)
	keyPat    = regexp.MustCompile(`\b(shp(?:ca|at|tka|pa)_[a-f0-9]{32})\b`)
	domainPat = regexp.MustCompile(`\b([a-zA-Z0-9-]+\.myshopify\.com)\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"shpca_", "shpat_", "shptka_", "shppa_"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Shopify secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, match := range keyPat.FindAllString(dataStr, -1) {
		uniqueKeys[strings.TrimSpace(match)] = struct{}{}
	}

	uniqueDomains := make(map[string]struct{})
	for _, match := range domainPat.FindAllString(dataStr, -1) {
		uniqueDomains[strings.TrimSpace(match)] = struct{}{}
	}

	for key := range uniqueKeys {
		if len(uniqueDomains) == 0 {
			// No domain found — emit unverified so token is not silently dropped.
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Shopify,
				Raw:          []byte(key),
				SecretParts:  map[string]string{"key": key},
			}
			s1.SetPrimarySecretValue(key)
			results = append(results, s1)
			continue
		}

		for domain := range uniqueDomains {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Shopify,
				Redacted:     domain,
				Raw:          []byte(key + domain),
				SecretParts:  map[string]string{"key": key, "store_url": domain},
			}
			s1.SetPrimarySecretValue(key)

			if verify {
				isVerified, extraData, verificationErr := verifyShopify(ctx, s.getClient(), domain, key)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, key)
				if isVerified {
					s1.ExtraData = extraData
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyShopify(ctx context.Context, client *http.Client, domain, key string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/admin/oauth/access_scopes.json", http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("X-Shopify-Access-Token", key)

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
		var scopes shopifyTokenAccessScopes
		if err := json.NewDecoder(res.Body).Decode(&scopes); err != nil {
			return false, nil, err
		}
		var handles []string
		for _, s := range scopes.AccessScopes {
			handles = append(handles, s.Handle)
		}
		return true, map[string]string{"access_scopes": strings.Join(handles, ",")}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

type shopifyTokenAccessScopes struct {
	AccessScopes []struct {
		Handle string `json:"handle"`
	} `json:"access_scopes"`
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Shopify
}

func (s Scanner) Description() string {
	return "An ecommerce platform, API keys can be used to access customer data"
}
