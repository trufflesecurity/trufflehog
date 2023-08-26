package satismeterprojectkey

import (
	"context"
	b64 "encoding/base64"
	"fmt"
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

	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"satismeter"}) + `\b([a-zA-Z0-9]{24})\b`)
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"satismeter"}) + `\b([a-zA-Z0-9]{4,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,12})\b`)
	passPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"satismeter"}) + `\b([a-zA-Z0-9!=@#$%^]{6,32})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("satismeter")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	emailmatches := emailPat.FindAllSubmatch(data, -1)
	passmatches := passPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := match[1]

		for _, emailmatch := range emailmatches {
			if len(emailmatch) != 2 {
				continue
			}
			resEmailMatch := emailmatch[1]

			for _, passmatch := range passmatches {
				if len(passmatch) != 2 {
					continue
				}
				resPassMatch := passmatch[1]

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_SatismeterProjectkey,
					Raw:          resMatch,
					RawV2:        append(resMatch, resPassMatch...),
				}

				if verify {

					data := append(resEmailMatch, ':')
					data = append(data, resPassMatch...)

					sEnc := b64.StdEncoding.EncodeToString(data)

					req, err := http.NewRequestWithContext(ctx, "GET", "https://app.satismeter.com/api/users?project="+string(resMatch), nil)

					if err != nil {
						continue
					}

					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SatismeterProjectkey
}
