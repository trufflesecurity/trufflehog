package pinata

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"
	"time"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pinata"}) + `\b([0-9a-z]{64})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"pinata"}) + `\b([0-9a-z]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pinata"}
}

// FromData will find and optionally verify Pinata secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := strings.TrimSpace(idMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Pinata,
				Raw:          []byte(resMatch),
			}

			if verify {
				timeout := 10 * time.Second
				client.Timeout = timeout
				payload := strings.NewReader(`{"pinataMetadata": {"name": "ItemStatus","keyvalues": {"ItemID": "Item001","CheckpointID": "Checkpoint002","Source": "CompanyA","WeightInKilos": 5.25}},"pinataContent": {"itemName": "exampleItemName","inspectedBy": "Inspector001","dataValues": []}}`)
				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.pinata.cloud/pinning/pinJSONToIPFS", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("pinata_api_key", resIdMatch)
				req.Header.Add("pinata_secret_api_key", resMatch)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Pinata
}
