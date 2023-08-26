package sinchmessage

import (
	"bytes"
	"context"
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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sinch"}) + `\b([a-z0-9]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"sinch"}) + `\b([a-z0-9]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sinch")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idmatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, idmatch := range idmatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := bytes.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SinchMessage,
				Raw:          resMatch,
			}

			if verify {
				payload := bytes.NewBuffer([]byte(`
				{
				"from": "447537454435",
				"to": [ "639668957581" ],
				"body": "This is a test message from your Sinch account"
				}`))

				url := []byte("https://sms.api.sinch.com/xms/v1/")
				url = append(url, resIdMatch...)
				url = append(url, []byte("/batches")...)

				req, err := http.NewRequestWithContext(ctx, "POST", string(url), payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")

				authorization := []byte("Bearer ")
				authorization = append(authorization, resMatch...)

				req.Header.Add("Authorization", string(authorization))
				res, err := client.Do(req)
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SinchMessage
}
