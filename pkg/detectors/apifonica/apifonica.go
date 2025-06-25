package apifonica

import (
	"context"
	b64 "encoding/base64"
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

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"apifonica"}) + `\b([0-9a-z]{11}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"apifonica"}
}

// FromData will find and optionally verify Apifonica secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeys, uniqueTokens = make(map[string]struct{}), make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[matches[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		for token := range uniqueTokens {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_ApiFonica,
				Raw:          []byte(key),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyApifonicaSecret(ctx, client, key, token)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyApifonicaSecret(ctx context.Context, client *http.Client, key string, token string) (bool, error) {
	data := fmt.Sprintf("%s:%s", key, token)
	sEnc := b64.StdEncoding.EncodeToString([]byte(data))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.apifonica.com/v2/accounts", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
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
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ApiFonica
}

func (s Scanner) Description() string {
	return "Apifonica is a cloud communication platform that provides APIs for messaging, voice, and other communication services. Apifonica keys can be used to access and manage these services."
}
