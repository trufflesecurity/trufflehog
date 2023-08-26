package captaindata

import (
	"bytes"
	"context"
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

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"captaindata"}) + `\b([0-9a-f]{64})\b`)
	projIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"captaindata"}) + `\b([0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("captaindata")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	projIdMatches := projIdPat.FindAllSubmatch(data, -1)

	for _, projIdMatch := range projIdMatches {
		if len(projIdMatch) != 2 {
			continue
		}
		resProjIdMatch := bytes.TrimSpace(projIdMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CaptainData,
				Raw:          resMatch,
				RawV2:        append(resProjIdMatch, resMatch...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.captaindata.co/v2/"+string(resProjIdMatch), nil)
				if err != nil {
					continue
				}
				req.Header.Add("x-api-key", string(resMatch))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CaptainData
}
