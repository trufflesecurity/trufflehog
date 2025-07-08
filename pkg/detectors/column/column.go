package column

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"column"}) + `\b((?:test|live)_[a-zA-Z0-9]{27})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"column"}
}

// FromData will find and optionally verify Column secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Column,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.column.com/entities", nil)
			if err != nil {
				continue
			}
			// req.SetBasicAuth(resMatch, "")
			req.Header.Add("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(resMatch))))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else {
					s1.Verified = false
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Column
}

func (s Scanner) Description() string {
	return "Column is a service used for managing entity data. Column keys can be used to access and modify this data."
}
