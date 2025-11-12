package notion

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 2 }

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"notion", "ntn_"}
}

// FromData will find and optionally verify Notion secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Notion,
			Raw:          []byte(resMatch),
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.notion.com/v1/users", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Notion-Version", "2022-06-28")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 || res.StatusCode == 403 {
					// if >= 200 and < 300, the secret is valid and has privileges for the /v1/users endpoint
					// If 403, the secret is valid, but does not have privileges for the /v1/users endpoint,
					// Notion returns 401 for all non-valid keys, thus 403 indicates it has fine-tuned permissions,
					// /v1/search, /v1/databases/*, etc. may work.
					s1.Verified = true
					s1.AnalysisInfo = map[string]string{"key": resMatch}

				}
			} else {
				s1.SetVerificationError(err, resMatch)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Notion
}

func (s Scanner) Description() string {
	return "Notion is a productivity tool that provides an all-in-one workspace for note-taking, project management, and collaboration. Notion API keys can be used to access and modify data within a user's Notion workspace."
}
