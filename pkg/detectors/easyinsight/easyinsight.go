package easyinsight

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"io"
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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"easyinsight", "easy-insight", "key"}) + `\b([0-9a-zA-Z]{20})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"easyinsight", "easy-insight", "id"}) + `\b([a-zA-Z0-9]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"easyinsight", "easy-insight"}
}

// FromData will find and optionally verify EasyInsight secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		resMatch := strings.TrimSpace(keyMatch[1])

		for _, idMatch := range idMatches {
			resIdMatch := strings.TrimSpace(idMatch[1])
			/*
				as key and id regex are same, the strings captured by both regex will be same.
				avoid processing when key is same as id. This will allow detector to process only different combinations
			*/
			if resMatch == resIdMatch {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_EasyInsight,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}

			if verify {
				auth := fmt.Sprintf("%s:%s", resIdMatch, resMatch)
				sEnc := b64.StdEncoding.EncodeToString([]byte(auth))

				req, err := http.NewRequestWithContext(ctx, "GET", "https://www.easy-insight.com/app/api/users.json", nil)
				if err != nil {
					continue
				}

				// add required headers to the request
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("Accept", "application/json")
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))

				res, err := client.Do(req)
				if err == nil {
					// discard the body content and close it at the end of each iteration.
					_, _ = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()

					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
			// if key id combination is verified, skip other idMatches for that key
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_EasyInsight
}

func (s Scanner) Description() string {
	return "EasyInsight is a business intelligence tool that provides data visualization and reporting. EasyInsight API keys can be used to access and manage data within the platform."
}
