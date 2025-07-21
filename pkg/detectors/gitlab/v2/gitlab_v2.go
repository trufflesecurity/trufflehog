package gitlab

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gitlab/v1"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int          { return 2 }
func (Scanner) CloudEndpoint() string { return "https://gitlab.com" }

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string { return []string{"glpat-"} }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gitlab
}

func (s Scanner) Description() string {
	return "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab Personal Access Tokens (PATs) can be used to authenticate and access GitLab resources."
}

// FromData will find and optionally verify Gitlab secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {

		resMatch := strings.TrimSpace(match[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Gitlab,
			Raw:          []byte(resMatch),
			ExtraData:    map[string]string{},
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/gitlab/",
			"version":        fmt.Sprintf("%d", s.Version()),
		}

		if verify {
			for _, endpoint := range s.Endpoints() {
				isVerified, extraData, verificationErr := v1.VerifyGitlab(ctx, s.getClient(), endpoint, resMatch)
				s1.Verified = isVerified
				maps.Copy(s1.ExtraData, extraData)

				s1.SetVerificationError(verificationErr)

				// for verified keys set the analysis info
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"key":  resMatch,
						"host": endpoint,
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}
