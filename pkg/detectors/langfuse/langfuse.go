package langfuse

import (
	"context"
	"fmt"
	"io"
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
	publicKey = regexp.MustCompile(detectors.PrefixRegex([]string{"langfuse"}) + `\b(pk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	secretKey = regexp.MustCompile(detectors.PrefixRegex([]string{"langfuse"}) + `\b(sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"pk-lf-", "sk-lf-"}
}

// FromData will find and optionally verify Langfuse secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	publicKeyMatches := make(map[string]struct{})
	for _, match := range publicKey.FindAllStringSubmatch(dataStr, -1) {
		publicKeyMatches[match[1]] = struct{}{}
	}

	secretKeyMatches := make(map[string]struct{})
	for _, match := range secretKey.FindAllStringSubmatch(dataStr, -1) {
		secretKeyMatches[match[1]] = struct{}{}
	}

	for pkMatch := range publicKeyMatches {
		for skMatch := range secretKeyMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Langfuse,
				Raw:          []byte(skMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, pkMatch, skMatch)
				s1.Verified = isVerified
				if verificationErr != nil {
					s1.SetVerificationError(verificationErr, pkMatch)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, pkMatch string, skMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloud.langfuse.com/api/public/projects", nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(pkMatch, skMatch)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Langfuse
}

func (s Scanner) Description() string {
	return "Langfuse is a platform for building and scaling AI applications. Langfuse API keys can be used to access these services."
}
