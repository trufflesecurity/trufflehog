package scrapingant

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"scrapingant"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"scrapingant"}
}

// FromData will find and optionally verify ScrapingAnt secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ScrapingAnt,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := verifyScrapingAnt(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ScrapingAnt
}

func (s Scanner) Description() string {
	return "ScrapingAnt is a web scraping service that provides API keys to authenticate and make requests to their scraping endpoints."
}

func verifyScrapingAnt(ctx context.Context, client *http.Client, apiKey string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// do not use google.com as url as it cannot be used under free subscription
	apiUrl := fmt.Sprintf("https://api.scrapingant.com/v1/general?url=example.com&x-api-key=%s", apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiUrl, http.NoBody)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, nil
	} else {
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
