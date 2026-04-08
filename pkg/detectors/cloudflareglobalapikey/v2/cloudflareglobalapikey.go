package cloudflareglobalapikey

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudflareglobalapikey/v1"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	v1.Scanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 2 }

var (
	client = common.SaneHttpClient()

	// 2026+ format: cfk_ prefix, sufficiently unique to match without keyword proximity.
	apiKeyV2Pat = regexp.MustCompile(`\b(cfk_[a-zA-Z0-9]{40}[a-f0-9]{8})\b`)

	emailPat = regexp.MustCompile(common.EmailPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"cfk_"}
}

// FromData will find and optionally verify CloudflareGlobalApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiKeyMatches := apiKeyV2Pat.FindAllStringSubmatch(dataStr, -1)

	uniqueEmailMatches := make(map[string]struct{})
	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmailMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, apiKeyMatch := range apiKeyMatches {
		apiKeyRes := strings.TrimSpace(apiKeyMatch[1])

		if len(uniqueEmailMatches) == 0 {
			// No email found; still report the token unverified.
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_CloudflareGlobalApiKey,
				Raw:          []byte(apiKeyRes),
			})
			continue
		}

		for emailMatch := range uniqueEmailMatches {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_CloudflareGlobalApiKey,
				Redacted:     emailMatch,
				Raw:          []byte(apiKeyRes),
				RawV2:        []byte(apiKeyRes + emailMatch),
			}

			if verify {
				s1.Verified = v1.VerifyGlobalAPIKey(ctx, client, apiKeyRes, emailMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CloudflareGlobalApiKey
}

func (s Scanner) Description() string {
	return "Cloudflare is a web infrastructure and website security company. Its services include content delivery network (CDN), DDoS mitigation, Internet security, and distributed domain name server (DNS) services. Cloudflare API keys (cfk_ prefixed, 2026+ format) can be used to access and modify these services."
}
