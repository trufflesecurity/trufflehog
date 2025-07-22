package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
	_ detectors.Versioner          = (*Scanner)(nil)
	_ detectors.CloudProvider      = (*Scanner)(nil)
)

func (Scanner) Version() int          { return 1 }
func (Scanner) CloudEndpoint() string { return "https://gitlab.com" }

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"gitlab"}) + `\b([a-zA-Z0-9][a-zA-Z0-9\-=_]{19,21})\b`)

	BlockedUserMessage = "403 Forbidden - Your account has been blocked"
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"gitlab"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gitlab
}

func (s Scanner) Description() string {
	return "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab API tokens can be used to access and modify repository data and other resources."
}

// FromData will find and optionally verify Gitlab secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		// ignore v2 detectors which have a prefix of `glpat-`
		if strings.Contains(match[0], "glpat-") {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		// to avoid false positives
		if detectors.StringShannonEntropy(resMatch) < 3.6 {
			continue
		}

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
				isVerified, extraData, verificationErr := VerifyGitlab(ctx, s.getClient(), endpoint, resMatch)
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

func VerifyGitlab(ctx context.Context, client *http.Client, baseEndpoint, resMatch string) (bool, map[string]string, error) {
	// there are 4 read 'scopes' for a gitlab token: api, read_user, read_repo, and read_registry
	// they all grant access to different parts of the API. I couldn't find an endpoint that every
	// one of these scopes has access to, so we just check an example endpoint for each scope. If any
	// of them contain data, we know we have a valid key, but if they all fail, we don't

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseEndpoint+"/api/v4/user", http.NoBody)
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}

	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, nil, err
	}

	// 200 means good key and has `read_user` scope
	// 403 means good key but not the right scope
	// 401 is bad key
	switch res.StatusCode {
	case http.StatusOK:
		return json.Valid(bodyBytes), nil, nil
	case http.StatusForbidden:
		// check if the user account is blocked or not
		stringBody := string(bodyBytes)
		if strings.Contains(stringBody, BlockedUserMessage) {
			return true, map[string]string{
				"blocked": "True",
			}, nil
		}

		// Good key but not the right scope
		return true, nil, nil
	case http.StatusUnauthorized:
		// Nothing to do; zero values are the ones we want
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
