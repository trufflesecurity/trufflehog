package paralleldots

import (
	"bytes"
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"paralleldots"}) + `\b([0-9A-Za-z]{43})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"paralleldots"}
}

// FromData will find and optionally verify Paralleldots secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ParallelDots,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := &bytes.Buffer{}
			writer := multipart.NewWriter(payload)
			fw, err := writer.CreateFormField("api_key")
			if err != nil {
				continue
			}
			_, err = io.Copy(fw, strings.NewReader(resMatch))
			if err != nil {
				continue
			}
			fw, err = writer.CreateFormField("text")
			if err != nil {
				continue
			}
			_, err = io.Copy(fw, strings.NewReader("sample text"))
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
				body := string(bodyBytes)
				if (res.StatusCode >= 200 && res.StatusCode < 300) && strings.Contains(body, "intent") {
					s1.Verified = true
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

func (s Scanner) Description() string {
	return "ParallelDots is an AI service offering various APIs for text analysis. API keys can be used to access these services."
}
