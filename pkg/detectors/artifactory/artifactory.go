package artifactory

import (
	"context"
	"fmt"
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

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{73}|\b[a-zA-Z0-9]{64})`)
	URLPat = regexp.MustCompile(`\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])\.jfrog\.io)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"artifactory"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Artifactory secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	URLmatches := URLPat.FindAllStringSubmatch(dataStr, -1)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	resURLMatch := ""
	for _, URLmatch := range URLmatches {
		if len(URLmatch) != 2 {
			continue
		}
		resURLMatch = strings.TrimSpace(URLmatch[1])
	}

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ArtifactoryAccessToken,
			Raw:          []byte(resMatch),
			RawV2:        []byte(resMatch + resURLMatch),
		}

		if verify {
			client := s.getClient()
			isVerified, verificationErr := verifyArtifactory(ctx, client, resURLMatch, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}
		results = append(results, s1)
	}

	return results, nil
}

func verifyArtifactory(ctx context.Context, client *http.Client, resURLMatch, resMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+resURLMatch+"/artifactory/api/storageinfo", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("X-JFrog-Art-Api", resMatch)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden:
		// https://jfrog.com/help/r/jfrog-rest-apis/error-responses
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ArtifactoryAccessToken
}
