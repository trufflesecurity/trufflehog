package endorlabs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyAndSecretPat = regexp.MustCompile(`\b(endr\+[a-zA-Z0-9-]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"endr+"}
}

// FromData will find and optionally verify Endorlabs secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := make(map[string]struct{})
	for _, match := range keyAndSecretPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[match[1]] = struct{}{}
	}

	secretMatches := make(map[string]struct{})
	for _, match := range keyAndSecretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[match[1]] = struct{}{}
	}

	for key := range keyMatches {
		for secret := range secretMatches {
			if key == secret { // Minor optimization
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_EndorLabs,
				Raw:          []byte(key),
				RawV2:        []byte(key + secret),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, extraData, verificationErr := verifyMatch(ctx, client, key, secret)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, key, secret)
			}

			results = append(results, s1)
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, key, secret string) (bool, map[string]string, error) {
	authData := fmt.Sprintf(`{"key":"%s", "secret":"%s"}`, key, secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.endorlabs.com/v1/auth/api-key", strings.NewReader(authData))
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Content-Type", "application/json")

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
		// If the endpoint returns useful information, we can return it as a map.
		return true, nil, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_EndorLabs
}

func (s Scanner) Description() string {
	return "Endorlabs provides API keys that can be used to authenticate and interact with its services. These keys should be kept confidential to prevent unauthorized access."
}
