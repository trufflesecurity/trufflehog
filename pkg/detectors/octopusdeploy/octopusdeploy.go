package octopusdeploy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Compile-time interface check
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Octopus Deploy API keys:
	// Format: API- followed by 29–34 uppercase letters or digits
	octopusTokenPat = regexp.MustCompile(
		`\b(API-[A-Z0-9]{29,34})\b`,
	)

	urlPat = regexp.MustCompile(`\b([a-z0-9-]+\.octopus\.app)\b`)
)

// Keywords used for fast pre-filtering
func (s Scanner) Keywords() []string {
	return []string{"octopus"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData scans for Octopus API tokens and optionally verifies them
func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	uniqueUrls := make(map[string]struct{})

	for _, urlMatch := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueUrls[urlMatch[1]] = struct{}{}
	}
	for _, match := range octopusTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for url := range uniqueUrls {
		for token := range uniqueTokens {
			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_OctopusDeploy,
				Raw:          []byte(token),
				RawV2:        []byte(fmt.Sprintf("%s:%s", url, token)),
			}

			if verify {
				verified, verificationErr := verifyOctopusToken(
					ctx,
					s.getClient(),
					url,
					token,
				)
				result.SetVerificationError(verificationErr, token)
				result.Verified = verified
			}

			results = append(results, result)
		}
	}

	return
}

func verifyOctopusToken(
	ctx context.Context,
	client *http.Client,
	baseUrl string,
	token string,
) (bool, error) {
	// API REFERENCE: https://trufflesec.octopus.app/api
	// DOCS: https://octopus.com/docs/octopus-rest-api
	url := &url.URL{
		Scheme: "https",
		Host:   baseUrl,
		Path:   "/api/users/me",
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url.String(),
		http.NoBody,
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("X-Octopus-ApiKey", token)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		return true, nil

	case http.StatusUnauthorized:
		// Invalid or revoked key
		return false, nil

	default:
		return false, fmt.Errorf(
			"unexpected HTTP response status %d",
			res.StatusCode,
		)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OctopusDeploy
}

func (s Scanner) Description() string {
	return "Octopus Deploy is a DevOps deployment automation platform. Octopus Deploy API keys can be used to automate deployments, manage projects, environments, and infrastructure resources."
}
