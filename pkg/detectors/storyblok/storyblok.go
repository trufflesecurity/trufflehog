package storyblok

import (
	"context"
	"errors"
	"fmt"
	"github.com/trufflesecurity/trufflehog/v3/pkg"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"storyblok"}) + `\b([0-9A-Za-z]{22}t{2})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"storyblok"}
}

// FromData will find and optionally verify Storyblok secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	var verifyError error

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Storyblok,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.storyblok.com/v1/cdn/spaces/me/?token="+resMatch, nil)
			if err != nil {
				continue
			}

			res, err := client.Do(req)
			if err != nil {
				urlErr := &url.Error{
					URL: req.URL.Host,
					Op:  req.Method,
					Err: errors.Unwrap(err),
				}
				verifyError = fmt.Errorf("%w: %s", pkg.ErrVerify, urlErr)
			} else {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else {
					// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, verifyError
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Storyblok
}
