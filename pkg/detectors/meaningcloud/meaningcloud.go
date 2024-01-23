package meaningcloud

import (
	"bytes"
	"context"
	"encoding/json"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"mime/multipart"
	"net/http"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"meaningcloud"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"meaningcloud"}
}

type response struct {
	DeepTime float64 `json:"deepTime"`
}

// FromData will find and optionally verify MeaningCloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_MeaningCloud,
			Raw:          []byte(resMatch),
		}

		if verify {
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			fw, err := writer.CreateFormField("key")
			if err != nil {
				continue
			}
			_, err = io.Copy(fw, strings.NewReader(resMatch))
			if err != nil {
				continue
			}
			fw, err = writer.CreateFormField("txt")
			if err != nil {
				continue
			}
			_, err = io.Copy(fw, strings.NewReader("test"))
			if err != nil {
				continue
			}
			writer.Close()
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.meaningcloud.com/lang-4.0/identification", bytes.NewReader(body.Bytes()))
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", writer.FormDataContentType())
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					var r response
					if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
						s1.SetVerificationError(err, resMatch)
						continue
					}
					if r.DeepTime > 0 {
						s1.Verified = true
					}
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MeaningCloud
}
