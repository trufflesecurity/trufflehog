package agora

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
	client *http.Client
}

const agoraURL = "https://api.agora.io"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"agora", "key", "token"}) + `\b([a-z0-9]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"agora", "secret"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"agora"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Agora secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, secret := range secretMatches {
			resSecret := strings.TrimSpace(secret[1])
			/*
				as both agora key and secretMatch has same regex, the set of strings keyMatch for both probably me same.
				we need to avoid the scenario where key is same as secretMatch. This will reduce the number of matches we process.
			*/
			if resMatch == resSecret {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Agora,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecret),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyAgora(ctx, client, resMatch, resSecret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyAgora(ctx context.Context, client *http.Client, resMatch, resSecret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agoraURL+"/dev/v1/projects", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(resSecret, resMatch)
	res, err := client.Do(req)

	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	// https://docs.agora.io/en/voice-calling/reference/agora-console-rest-api#get-all-projects
	switch res.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Agora
}

func (s Scanner) Description() string {
	return "Agora is a real-time engagement platform providing APIs for voice, video, and messaging. Agora API keys can be used to access and manage these services."
}
