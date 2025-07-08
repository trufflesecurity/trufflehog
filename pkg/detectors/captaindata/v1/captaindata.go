package captaindata

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

func (s Scanner) Version() int { return 1 }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"captaindata"}) + `\b([0-9a-f]{64})\b`)
	projIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"captaindata"}) + `\b([0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"captaindata"}
}

// FromData will find and optionally verify CaptainData secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	projIdMatches := projIdPat.FindAllStringSubmatch(dataStr, -1)

	for _, projIdMatch := range projIdMatches {
		resProjIdMatch := strings.TrimSpace(projIdMatch[1])

		for _, match := range matches {
			resMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CaptainData,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resProjIdMatch + resMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.captaindata.co/v2/"+resProjIdMatch, nil)
				if err != nil {
					continue
				}
				req.Header.Add("x-api-key", resMatch)
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
	return detectorspb.DetectorType_CaptainData
}

func (s Scanner) Description() string {
	return "CaptainData is a service for automating data extraction and processing. The API keys can be used to access and control these automation processes."
}
