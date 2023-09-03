package gocanvas

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client   = common.SaneHttpClient()
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"gocanvas"}) + `\b([0-9A-Za-z/+]{43}=[ \r\n]{1})`)
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"gocanvas"}) + `\b([\w\.-]+@[\w-]+\.[\w\.-]{2,5})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("gocanvas")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	emailMatches := emailPat.FindAllSubmatch(data, -1)

	for _, emailMatch := range emailMatches {
		if len(emailMatch) != 2 {
			continue
		}
		resEmailMatch := bytes.TrimSpace(emailMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GoCanvas,
				Raw:          resMatch,
			}

			if verify {
				payload := url.Values{}
				payload.Add("username", string(resEmailMatch))

				req, err := http.NewRequest("GET", "https://www.gocanvas.com/apiv2/forms.xml", bytes.NewBuffer([]byte(payload.Encode())))
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(resMatch)))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					body, errBody := io.ReadAll(res.Body)

					if errBody == nil {
						response := Response{}
						if err := xml.Unmarshal(body, &response); err != nil {
							continue
						}

						if res.StatusCode >= 200 && res.StatusCode < 300 && response.Error == nil {
							s1.Verified = true
						} else {
							if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
				}
			}
			results = append(results, s1)
		}
	}

	return results, nil
}

type Response struct {
	Error []struct {
		ErrorCode int `xml:"ErrorCode"`
	} `xml:"Error"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GoCanvas
}
