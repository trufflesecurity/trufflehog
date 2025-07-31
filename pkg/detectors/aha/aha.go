package aha

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"aha"}) + `\b([0-9a-f]{64})\b`)
	URLPat = regexp.MustCompile(`\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])\.aha\.io)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"aha.io"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Aha
}

func (s Scanner) Description() string {
	return "Aha is a product management software suite. Aha API keys can be used to access and modify product data and workflows."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Aha secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueFoundUrls = make(map[string]struct{})

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range URLPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueFoundUrls[match[1]] = struct{}{}
	}

	// if no url was found use the default
	if len(uniqueFoundUrls) == 0 {
		uniqueFoundUrls["aha.io"] = struct{}{}
	}

	for _, match := range matches {
		for url := range uniqueFoundUrls {
			resMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Aha,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + url),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyAha(ctx, client, resMatch, url)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyAha(ctx context.Context, client *http.Client, resMatch, resURLMatch string) (bool, error) {
	url := fmt.Sprintf("https://%s/api/v1/me", resURLMatch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/vnd.aha+json; version=3")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	// https://www.aha.io/api
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusNotFound, http.StatusForbidden:
		// 403 is a known case where an account is inactive bc of a trial ending or payment issue
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
