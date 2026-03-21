package newrelicbrowserkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(NRBR-[0-9a-f]{19})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string { return []string{"nrbr-"} }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NewRelicBrowserKey
}

func (s Scanner) Description() string {
	return "A New Relic Browser API key is used to authenticate and enable browser monitoring, allowing New Relic to collect performance data, page views, and user interactions from web applications to track and optimize front-end performance."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(resMatch),
			Redacted:     resMatch[:8] + "...",
		}

		if verify {
			isVerified, extraData, verificationErr := s.verify(ctx, resMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verify checks if the key is valid by making a request to New Relic's Browser API endpoint.
// There are separate endpoints for US and EU region keys, so we check both.
// These endpoints are not documented anywhere because they are used internally by the New Relic Browser agent
// The endpoints were discovered by observing network traffic from the New Relic Browser agent
// A 400 Bad Request response indicates that the key is valid but the request is malformed (because we are not sending the expected payload)
// A 403 Forbidden response indicates that the key is invalid or revoked
func (s Scanner) verify(ctx context.Context, key string) (bool, map[string]string, error) {
	regionUrls := map[string]string{
		"us": "https://bam.nr-data.net/1/",
		"eu": "https://bam.eu01.nr-data.net/1/",
	}
	errs := make([]error, 0, len(regionUrls))
	for region, regionUrl := range regionUrls {
		verified, err := s.verifyRegion(ctx, key, regionUrl)
		if err != nil {
			errs = append(errs, fmt.Errorf("error verifying region %s: %w", region, err))
			continue
		}
		if verified {
			return true, map[string]string{"region": region}, nil
		}
	}
	return false, nil, errors.Join(errs...)
}

func (s Scanner) verifyRegion(ctx context.Context, key string, regionUrl string) (bool, error) {
	fullUrl, err := url.JoinPath(regionUrl, key)
	if err != nil {
		return false, fmt.Errorf("error constructing URL: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, fullUrl, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("error constructing request: %w", err)
	}

	client := s.getClient()

	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusBadRequest:
		return true, nil
	case http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
