package roaring

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	clientPat = regexp.MustCompile(detectors.PrefixRegex([]string{"roaring"}) + `\b([0-9A-Za-z_-]{28})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"roaring"}) + `\b([0-9A-Za-z_-]{28})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("roaring")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	clientMatches := clientPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, clientMatch := range clientMatches {
		if len(clientMatch) != 2 {
			continue
		}
		resClient := bytes.TrimSpace(clientMatch[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecret := bytes.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Roaring,
				Raw:          resClient,
				RawV2:        append(resClient, resSecret...),
			}

			if verify {
				data := append(resClient, []byte(":")...)
				data = append(data, resSecret...)
				sEnc := b64.StdEncoding.EncodeToString(data)
				payload := bytes.NewBuffer([]byte("grant_type=client_credentials"))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.roaring.io/token", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
				res, err := client.Do(req)
				if err == nil && res != nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resSecret, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Roaring
}
