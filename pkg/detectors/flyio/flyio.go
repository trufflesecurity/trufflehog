package flyio

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
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(FlyV1 fm\d+_[A-Za-z0-9+\/=,_-]{500,700})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"FlyV1"}
}

// FromData will find and optionally verify Flyio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FlyIO,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, match)

			s1.Verified = isVerified
			if verificationErr != nil {
				s1.SetVerificationError(verificationErr, match)
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Not setting org_slug intentionally, as it's not required for the token to be valid.
	// Initially, an organization named "personal" is created by FlyIO when the user signs up for an account. We cannot rely on this as it can be deleted.
	// 403 is returned if incorrect org_slug is sent.
	// 401 is returned if the token is invalid.
	// 400 is returned if the token is valid but no org_slug is sent.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.machines.dev/v1/apps?org_slug=", http.NoBody)
	if err != nil {
		return false, nil
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusBadRequest:
		// Not setting org_slug returns a 400 error, which is expected.
		return true, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil
	default:
		err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FlyIO
}

func (s Scanner) Description() string {
	return "Fly.io is a platform for running applications globally. Fly.io tokens can be used to access the Fly.io API and manage applications."
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	// ignore AAAAAA for Flyio detector
	if strings.Contains(string(result.Raw), "AAAAAA") {
		return false, ""
	}

	// For non-matching patterns, fall back to default false positive logic
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}
