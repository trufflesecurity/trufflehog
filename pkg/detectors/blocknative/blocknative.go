package blocknative

import (
	"bytes"
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"blocknative"}) + `\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("blocknative")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_BlockNative,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.blocknative.com/gasprices/blockprices", nil)
			if err != nil {
				continue
			}

			req.Header.Add("Authorization", string(resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				if !bytes.Contains(bodyBytes, []byte("valid")) {
					s1.Verified = true
				} else {
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BlockNative
}
