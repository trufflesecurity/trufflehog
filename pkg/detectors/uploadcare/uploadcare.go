package uploadcare

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
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
	keyPat       = regexp.MustCompile(detectors.PrefixRegex([]string{"uploadcare"}) + `\b([a-z0-9]{20})\b`)
	publicKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"uploadcare"}) + `\b([a-z0-9]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"uploadcare"}
}

// FromData will find and optionally verify UploadCare secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	publicMatches := publicKeyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, publicMatch := range publicMatches {
			publicKeyMatch := strings.TrimSpace(publicMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_UploadCare,
				Raw:          []byte(resMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.uploadcare.com/files/", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/vnd.uploadcare-v0.5+json")
				req.Header.Add("Authorization", fmt.Sprintf("Uploadcare.Simple %s:%s", publicKeyMatch, resMatch))
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
	return detectorspb.DetectorType_UploadCare
}

func (s Scanner) Description() string {
	return "UploadCare is a service for handling file uploads and transformations. UploadCare keys can be used to manage and access files within the UploadCare system."
}
