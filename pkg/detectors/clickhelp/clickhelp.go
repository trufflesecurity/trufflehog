package clickhelp

import (
	"bytes"
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

	serverPat = regexp.MustCompile(`\b([0-9A-Za-z]{3,20}.try.clickhelp.co)\b`)
	emailPat  = regexp.MustCompile(`\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-z]+)\b`)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"clickhelp"}) + `\b([0-9A-Za-z]{24})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("clickhelp")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	serverMatches := serverPat.FindAllSubmatch(data, -1)
	emailMatches := emailPat.FindAllSubmatch(data, -1)
	keyMatches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range serverMatches {
		if len(match) != 2 {
			continue
		}
		resServer := bytes.TrimSpace(match[1])

		for _, emailMatch := range emailMatches {
			if len(emailMatch) != 2 {
				continue
			}
			resEmail := bytes.TrimSpace(emailMatch[1])
			for _, keyMatch := range keyMatches {
				if len(keyMatch) != 2 {
					continue
				}
				resKey := bytes.TrimSpace(keyMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ClickHelp,
					Raw:          resServer,
					RawV2:        append(resServer, resEmail...),
				}

				if verify {
					data := bytes.Join([][]byte{resEmail, resKey}, []byte(":"))
					sEnc := b64.StdEncoding.EncodeToString(data)
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/v1/projects", string(resServer)), nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							if detectors.IsKnownFalsePositive(resServer, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_ClickHelp
}
