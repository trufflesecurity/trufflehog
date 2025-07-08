package neutrinoapi

import (
	"bytes"
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"neutrinoapi"}) + `\b([a-zA-Z0-9]{48})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"neutrinoapi"}) + `\b([a-zA-Z0-9]{6,24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"neutrinoapi"}
}

// FromData will find and optionally verify NeutrinoApi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_NeutrinoApi,
				Raw:          []byte(resMatch),
			}

			if verify {
				body := &bytes.Buffer{}
				writer := multipart.NewWriter(body)
				fw, err := writer.CreateFormField("url")
				if err != nil {
					continue
				}
				_, err = io.Copy(fw, strings.NewReader("https://google.com"))
				if err != nil {
					continue
				}
				writer.Close()
				req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://neutrinoapi.net/url-info?user-id=%s&api-key=%s", resIdMatch, resMatch), bytes.NewReader(body.Bytes()))
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", writer.FormDataContentType())
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NeutrinoApi
}

func (s Scanner) Description() string {
	return "Neutrino API provides a variety of services including data tools, security tools, and more. Neutrino API keys can be used to access these services."
}
