package shotstack

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"shotstack"}) + `\b([a-zA-Z0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"shotstack"}
}

// FromData will find and optionally verify Shotstack secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Shotstack,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader(`{
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
			}`)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.shotstack.io/stage/render", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Accept", "application/json")
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Shotstack
}

func (s Scanner) Description() string {
	return "Shotstack is a video editing API service. Shotstack API keys can be used to access and utilize the video rendering and editing capabilities of the Shotstack platform."
}
