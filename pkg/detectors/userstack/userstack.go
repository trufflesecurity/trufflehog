package userstack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"userstack"}) + `\b([a-z0-9]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("userstack")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_UserStack,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.userstack.com/detect?access_key=%s&ua=Mozilla/5.0", string(resMatch)), nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err == nil {
					valid := bytes.Contains(bodyBytes, []byte(`is_mobile_device`)) || bytes.Contains(bodyBytes, []byte(`"info":"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."`))
					defer res.Body.Close()
					if valid {
						s1.Verified = true
					} else {
						s1.Verified = false
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_UserStack
}
