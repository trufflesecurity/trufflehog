package artifactory

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Keep the regexp patterns unchanged
	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{73})`)
	URLPat = regexp.MustCompile(`\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])\.jfrog\.io)`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("artifactory")}
}

// FromData will find and optionally verify Artifactory secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	URLmatches := URLPat.FindAllSubmatch(data, -1)
	matches := keyPat.FindAllSubmatch(data, -1)

	var resURLMatch []byte

	for _, URLmatch := range URLmatches {
		if len(URLmatch) != 2 {
			continue
		}
		resURLMatch = bytes.TrimSpace(URLmatch[1])
	}

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ArtifactoryAccessToken,
			Raw:          resMatch,
			RawV2:        append(resMatch, resURLMatch...),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://"+string(resURLMatch)+"/artifactory/api/storageinfo", nil)
			if err != nil {
				continue
			}
			req.Header.Add("X-JFrog-Art-Api", string(resMatch))
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
	return detectorspb.DetectorType_ArtifactoryAccessToken
}
