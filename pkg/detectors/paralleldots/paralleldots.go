package paralleldots

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"paralleldots"}) + `\b([0-9A-Za-z]{43})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("paralleldots")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ParallelDots,
			Raw:          resMatch,
		}

		if verify {
			payload := &bytes.Buffer{}
			writer := multipart.NewWriter(payload)
			fw, err := writer.CreateFormField("api_key")
			if err != nil {
				continue
			}
			_, err = io.Copy(fw, bytes.NewReader(resMatch))
			if err != nil {
				continue
			}
			fw, err = writer.CreateFormField("text")
			if err != nil {
				continue
			}
			_, err = io.Copy(fw, bytes.NewReader([]byte("sample text")))
			if err != nil {
				continue
			}
			writer.Close()
			req, err := http.NewRequestWithContext(ctx, "POST", "https://apis.paralleldots.com/v4/intent", bytes.NewReader(payload.Bytes()))
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", writer.FormDataContentType())
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				if (res.StatusCode >= 200 && res.StatusCode < 300) && bytes.Contains(bodyBytes, []byte("intent")) {
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
	return detectorspb.DetectorType_ParallelDots
}
