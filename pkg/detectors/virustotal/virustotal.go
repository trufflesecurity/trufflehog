package virustotal

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"virustotal"}) + `\b([a-f0-9]{64})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("virustotal")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_VirusTotal,
			Raw:          resMatch,
		}

		if verify {
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			fw, err := writer.CreateFormField("url")
			if err != nil {
				continue
			}
			_, err = io.Copy(fw, bytes.NewBufferString("https://www.amazon.com"))
			if err != nil {
				continue
			}
			writer.Close()
			req, err := http.NewRequestWithContext(ctx, "POST", "https://www.virustotal.com/api/v3/urls", body)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", writer.FormDataContentType())
			req.Header.Add("x-apikey", string(resMatch))
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_VirusTotal
}
