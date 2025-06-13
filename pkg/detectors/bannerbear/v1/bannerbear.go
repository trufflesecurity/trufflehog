package bannerbear

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

type Scanner struct{}

func (s Scanner) Version() int { return 1 }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bannerbear"}) + `\b([0-9a-zA-Z]{22}tt)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bannerbear"}
}

// FromData will find and optionally verify Bannerbear secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Bannerbear,
			Raw:          []byte(resMatch),
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			isVerified, verificationErr := verifyBannerBear(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bannerbear
}

func (s Scanner) Description() string {
	return "Bannerbear is an API for generating dynamic images, videos, and GIFs. Bannerbear API keys can be used to access and manipulate these resources."
}

// docs: https://developers.bannerbear.com/
func verifyBannerBear(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.bannerbear.com/v2/auth", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

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
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
