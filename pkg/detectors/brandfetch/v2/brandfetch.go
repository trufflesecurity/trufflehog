package brandfetch

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

func (s Scanner) Version() int { return 2 }

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_             detectors.Detector  = (*Scanner)(nil)
	_             detectors.Versioner = (*Scanner)(nil)
	defaultClient                     = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"brandfetch"}) + `([a-zA-Z0-9=+/\-_!@#$%^&*()]{43}=)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"brandfetch"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Brandfetch
}

func (s Scanner) Description() string {
	return "Brandfetch is a service that provides brand data, including logos, colors, fonts, and more. Brandfetch API keys can be used to access this data."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// FromData will find and optionally verify Brandfetch secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Brandfetch,
			Raw:          []byte(match),
			ExtraData:    map[string]string{"version": strconv.Itoa(s.Version())},
		}

		if verify {
			isVerified, verificationErr := VerifyMatch(ctx, s.getClient(), match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

// verifyMatch checks if the provided Brandfetch token is valid by making a request to the Brandfetch API.
// https://docs.brandfetch.com/docs/getting-started
func VerifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.brandfetch.io/v2/brands/google.com", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
