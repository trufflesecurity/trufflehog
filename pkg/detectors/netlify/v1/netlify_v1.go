package netlify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"netlify"}) + `\b([A-Za-z0-9_-]{43,45})\b`)
)

const (
	rotationGuideUrl = "https://howtorotate.com/docs/tutorials/netlify/"
	verificationUrl  = "https://api.netlify.com/api/v1/sites"
)

func (Scanner) Version() int { return 1 }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"netlify"}
}

// FromData will find and optionally verify Netlify secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Netlify,
			Raw:          []byte(match),
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": rotationGuideUrl,
			"version":        strconv.Itoa(s.Version()),
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)

			if s1.Verified {
				s1.AnalysisInfo = map[string]string{"key": match}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verificationUrl, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
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
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Netlify
}

func (s Scanner) Description() string {
	return "Netlify is a cloud platform for web developers that provides hosting and serverless backend services for web applications and static websites. Netlify API keys can be used to manage sites, deploy applications, and access various services offered by the platform."
}
