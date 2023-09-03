package shotstack

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"shotstack"}) + `\b([a-zA-Z0-9]{40})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("shotstack")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Shotstack,
			Raw:          resMatch,
		}

		if verify {
			payload := bytes.NewBuffer([]byte(`{
				"timeline":{
				   "soundtrack":{
					  "src":"https://s3-ap-southeast-2.amazonaws.com/shotstack-assets/music/moment.mp3",
					  "effect":"fadeOut"
				   },
				   "background":"#000000",
				   "tracks":[
					  {
						 "clips":[
							{
							   "asset": {
								  "type":"title",
								  "text":"Hello World",
								  "style":"minimal"
							   },
							   "start":0,
							   "length":5,
							   "transition":{
								  "in":"fade",
								  "out":"fade"
							   }
							}
						 ]
					  }
				   ]
				},
				"output":{"format":"mp4", "resolution":"sd"
				}
			}`))
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.shotstack.io/stage/render", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Accept", "application/json")
			req.Header.Add("x-api-key", string(resMatch))
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Shotstack
}
