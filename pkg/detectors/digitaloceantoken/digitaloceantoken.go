package digitaloceantoken

import (
	"context"
	"fmt"
	"net/http"

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

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"ocean", "do"}) + `\b([A-Za-z0-9_-]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"digitalocean"}
}

// FromData will find and optionally verify DigitalOceanToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	var uniqueTokens = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[matches[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DigitalOceanToken,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, verificationErr := verifyDigitalOceanToken(ctx, client, token)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
			if s1.Verified {
				s1.AnalysisInfo = map[string]string{
					"key": token,
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyDigitalOceanToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Ref: https://docs.digitalocean.com/reference/api/digitalocean/#tag/Account

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.digitalocean.com/v2/account", nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DigitalOceanToken
}

func (s Scanner) Description() string {
	return "DigitalOcean is a cloud infrastructure provider offering cloud services to help deploy, manage, and scale applications. DigitalOcean tokens can be used to access and manage these services."
}
