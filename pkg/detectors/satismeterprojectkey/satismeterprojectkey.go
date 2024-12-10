package satismeterprojectkey

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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	projectPat = regexp.MustCompile(detectors.PrefixRegex([]string{"satismeter"}) + `\b([a-zA-Z0-9]{24})\b`)
	tokenPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"satismeter"}) + `\b([A-Za-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"satismeter"}
}

// FromData will find and optionally verify SatismeterProjectkey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueProjectMatches, uniqueTokenMatches := make(map[string]struct{}), make(map[string]struct{})
	for _, match := range projectPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueProjectMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokenMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for projectID := range uniqueProjectMatches {
		for token := range uniqueTokenMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SatismeterProjectkey,
				Raw:          []byte(projectID),
				RawV2:        []byte(projectID + token),
			}

			if verify {
				isVerified, verificationErr := verifySatisMeterApp(ctx, client, projectID, token)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, token)
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SatismeterProjectkey
}

func (s Scanner) Description() string {
	return "Satismeter is a customer feedback platform. Satismeter project keys can be used to access project-specific data and manage feedback settings."
}

func verifySatisMeterApp(ctx context.Context, client *http.Client, projectID, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://app.satismeter.com/api/users?project="+projectID, nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	case http.StatusNotFound:
		// if project id is not found, api return 401
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
