package gitlaboauthapplication

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var keyPat = regexp.MustCompile(`\b(gloas-[a-f0-9]{64})\b`)

func (s Scanner) Keywords() []string {
	return []string{"gloas-"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_GitlabOauthApplication,
			Raw:          []byte(match),
		})
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GitlabOauthApplication
}

func (s Scanner) Description() string {
	return "GitLab OAuth application secrets (client secrets) authenticate GitLab OAuth applications and must be paired with the application ID for token exchange."
}
