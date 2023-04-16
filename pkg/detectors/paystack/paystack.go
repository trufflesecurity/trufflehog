package paystack

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
	// TODO: support live key
	keyPat = regexp.MustCompile(`\b(sk\_[a-z]{1,}\_[A-Za-z0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"paystack"}
}

// FromData will find and optionally verify Paystack secrets in a given set of bytes.
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
			DetectorType: detectorspb.DetectorType_Paystack,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.paystack.co/customer", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, false) {
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
	return detectorspb.DetectorType_Paystack
}
