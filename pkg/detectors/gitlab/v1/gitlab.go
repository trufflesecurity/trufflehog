package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
)

func (Scanner) Version() int            { return 1 }
func (Scanner) DefaultEndpoint() string { return "https://gitlab.com" }

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"gitlab"}) + `\b([a-zA-Z0-9\-=_]{20,22})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"gitlab"}
}

// FromData will find and optionally verify Gitlab secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		// ignore v2 detectors which have a prefix of `glpat-`
		if strings.Contains(match[0], "glpat-") {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Gitlab,
			Raw:          []byte(resMatch),
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/gitlab/",
			"version":        fmt.Sprintf("%d", s.Version()),
		}

		if verify {
			isVerified, verificationErr := s.verifyGitlab(ctx, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) verifyGitlab(ctx context.Context, resMatch string) (bool, error) {
	// there are 4 read 'scopes' for a gitlab token: api, read_user, read_repo, and read_registry
	// they all grant access to different parts of the API. I couldn't find an endpoint that every
	// one of these scopes has access to, so we just check an example endpoint for each scope. If any
	// of them contain data, we know we have a valid key, but if they all fail, we don't

	client := s.client
	if client == nil {
		client = defaultClient
	}
	for _, baseURL := range s.Endpoints(s.DefaultEndpoint()) {
		// test `read_user` scope
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v4/user", nil)
		if err != nil {
			continue
		}

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
		res, err := client.Do(req)
		if err != nil {
			return false, err
		}

		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}

		// 200 means good key and has `read_user` scope
		// 403 means good key but not the right scope
		// 401 is bad key
		switch res.StatusCode {
		case http.StatusOK:
			return json.Valid(body), nil
		case http.StatusForbidden:
			// Good key but not the right scope
			return true, nil
		case http.StatusUnauthorized:
			// Nothing to do; zero values are the ones we want
			return false, nil
		default:
			return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		}

	}
	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gitlab
}
