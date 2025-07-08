package scalr

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

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"scalr"}) + `\b([0-9a-zA-Z._]{136})`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"scalr"}) + `\b([0-9a-z]{4,50})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"scalr"}
}

// FromData will find and optionally verify Scalr secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, idmatch := range idmatches {
			resIdMatch := strings.TrimSpace(idmatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Scalr,
				Raw:          []byte(resMatch),
			}

			if verify {
				url := fmt.Sprintf("https://%s.scalr.io/api/iacp/v3/agents", resIdMatch)
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
				req.Header.Add("Content-Type", "application/vnd.api+json")
				req.Header.Add("Prefer", "profile=preview")
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
	return detectorspb.DetectorType_Scalr
}

func (s Scanner) Description() string {
	return "Scalr is a cloud management platform that allows users to manage and automate cloud infrastructure. Scalr keys can be used to access and manage cloud resources within the Scalr platform."
}
