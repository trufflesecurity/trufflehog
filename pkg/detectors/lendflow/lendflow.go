package lendflow

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
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

	// Keeping the regexp patterns unchanged
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"lendflow"}) + `\b([a-zA-Z0-9]{36}\.[a-zA-Z0-9]{235}\.[a-zA-Z0-9]{32}\-[a-zA-Z0-9]{47}\-[a-zA-Z0-9_]{162}\-[a-zA-Z0-9]{42}\-[a-zA-Z0-9_]{40}\-[a-zA-Z0-9_]{66}\-[a-zA-Z0-9_]{59}\-[a-zA-Z0-9]{7}\-[a-zA-Z0-9_]{220})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("lendflow")}
}

// FromData will find and optionally verify Lendflow secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Lendflow,
			Raw:          resMatch,
		}

		if verify {
			timeout := 10 * time.Second
			client.Timeout = timeout
			req, err := http.NewRequestWithContext(ctx, "GET", "https://app.lendflow.io/api/v1/deals", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			req.Header.Add("Accept", "application/json")
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
	return detectorspb.DetectorType_Lendflow
}
