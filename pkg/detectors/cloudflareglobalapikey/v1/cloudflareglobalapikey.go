package cloudflareglobalapikey

import (
	"context"
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

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 1 }

var (
	client = common.SaneHttpClient()

	// Pre-2026 format: lowercase hex, 37-45 chars, requires "cloudflare" keyword nearby.
	apiKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudflare"}) + `\b([a-f0-9]{37,45})\b`)

	emailPat = regexp.MustCompile(common.EmailPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cloudflare"}
}

// FromData will find and optionally verify CloudflareGlobalApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiKeyMatches := apiKeyPat.FindAllStringSubmatch(dataStr, -1)

	uniqueEmailMatches := make(map[string]struct{})
	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmailMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, apiKeyMatch := range apiKeyMatches {
		apiKeyRes := strings.TrimSpace(apiKeyMatch[1])

		for emailMatch := range uniqueEmailMatches {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_CloudflareGlobalApiKey,
				Redacted:     emailMatch,
				Raw:          []byte(apiKeyRes),
				SecretParts: map[string]string{
					"key":   apiKeyRes,
					"email": emailMatch,
				},
				RawV2: []byte(apiKeyRes + emailMatch),
			}

			if verify {
				s1.Verified = VerifyGlobalAPIKey(ctx, client, apiKeyRes, emailMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

// VerifyGlobalAPIKey checks if a Cloudflare Global API Key is valid.
func VerifyGlobalAPIKey(ctx context.Context, client *http.Client, apiKey, email string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.cloudflare.com/client/v4/user", nil)
	if err != nil {
		return false
	}
	req.Header.Add("X-Auth-Email", email)
	req.Header.Add("X-Auth-Key", apiKey)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 300
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CloudflareGlobalApiKey
}

func (s Scanner) Description() string {
	return "Cloudflare is a web infrastructure and website security company. Its services include content delivery network (CDN), DDoS mitigation, Internet security, and distributed domain name server (DNS) services. Cloudflare API keys can be used to access and modify these services."
}
