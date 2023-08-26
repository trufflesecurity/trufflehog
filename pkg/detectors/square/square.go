package square

import (
	"bytes"
	"context"
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
	secretPat = regexp.MustCompile(string(detectors.PrefixRegex([]string{"square"})) + `(EAAA[a-zA-Z0-9\-\+\=]{60})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("EAAA")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	if !bytes.Contains(bytes.ToLower(data), []byte("square")) {
		return
	}

	secMatches := secretPat.FindAllSubmatch(data, -1)
	for _, secMatch := range secMatches {
		if len(secMatch) != 2 {
			continue
		}
		res := bytes.TrimSpace(secMatch[1])

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Square,
			Raw:          res,
		}
		if verify {
			baseURL := "https://connect.squareupsandbox.com/v2/merchants"
			client := common.SaneHttpClient()
			req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(res)))
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close()
				if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusForbidden {
					s.Verified = true
				}
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(s.Raw, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Square
}
