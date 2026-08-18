package sonarcloud

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 2 }

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(sqco_[[:alnum:]]{59})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sqco_"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// FromData will find and optionally verify SonarCloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokenMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokenMatches[match[1]] = struct{}{}
	}

	for match := range uniqueTokenMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_SonarCloud,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			isVerified, verificationErr := s.verifyMatch(ctx, s.getClient(), match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyMatch attempts to validate a SonarCloud token.
func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Format-compliant (lowercase alphanumeric + hyphens) dummy key that won't match a
	// real organization, so the API returns 404 rather than rejecting it as malformed.
	organizationKey := "nonexistent-org-9f2a7c4e1b8d4a6f"
	url := fmt.Sprintf("https://sonarcloud.io/api/projects/search?organization=%s", organizationKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to perform request: %w", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// The official Sonar API docs don't document the response codes for this
	// endpoint, but community evidence indicates 403 is returned when the
	// token is valid but lacks org-admin permissions on the queried org:
	// https://community.sonarsource.com/t/api-access-issue-for-read-only-user-despite-ui-access/140025
	// https://community.sonarsource.com/t/http-403-when-accessing-api-projects-search-but-other-endpoint-works-like-components/20668
	switch res.StatusCode {
	case http.StatusOK, http.StatusNotFound, http.StatusForbidden:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SonarCloud
}

func (s Scanner) Description() string {
	return "SonarCloud is a cloud-based code quality and security service. SonarCloud tokens can be used to access project analysis and quality reports."
}
