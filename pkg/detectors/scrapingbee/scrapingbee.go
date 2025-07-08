package scrapingbee

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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ScrapingBee
}

func (s Scanner) Description() string {
	return "ScrapingBee is a web scraping service that handles headless browsers and proxies for you. ScrapingBee API keys can be used to access and control web scraping tasks."
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"scrapingbee", "scraping bee", "scraping-bee", "scraping_bee"}
}

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"scraping[ _-]?bee"}) + `\b([A-Z0-9]{80})\b`)
)

// FromData will find and optionally verify ScrapingBee secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		if detectors.StringShannonEntropy(m) < 3.5 {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}

	for key := range uniqueMatches {
		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_ScrapingBee,
			Raw:          []byte(key),
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}

			isVerified, verificationErr := verifyMatch(ctx, s.client, key)
			r.Verified = isVerified
			r.SetVerificationError(verificationErr, key)
		}

		results = append(results, r)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.scrapingbee.com/api/v1/?api_key="+key+"&url=https://httpbin.org/anything?json&render_js=false", nil)
	if err != nil {
		return false, err
	}

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
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
