package html2pdf

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

type html2pdfRequest struct {
	HTML   string `json:"html"`
	ApiKey string `json:"apiKey"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Keeping the regexp patterns unchanged
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"html2pdf"}) + `\b([a-zA-Z0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("html2pdf")}
}

// FromData will find and optionally verify Html2Pdf secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Html2Pdf,
			Raw:          resMatch,
		}

		if verify {
			req := html2pdfRequest{
				HTML:   "Helloworld",
				ApiKey: string(resMatch),
			}
			reqJson, _ := json.Marshal(&req)
			reqBuf := bytes.NewReader(reqJson)
			res, err := http.Post("https://api.html2pdf.app/v1/generate", "application/json", reqBuf)

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
	return detectorspb.DetectorType_Html2Pdf
}
