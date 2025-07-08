package lokalisetoken

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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"lokalise"}) + `\b([a-z0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"lokalise"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LokaliseToken
}

func (s Scanner) Description() string {
	return "Lokalise is a translation management system that helps teams to manage and automate their localization process. Lokalise tokens can be used to access its API and modify project data."
}

// FromData will find and optionally verify LokaliseToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LokaliseToken,
			Raw:          []byte(resMatch),
			ExtraData:    make(map[string]string),
		}

		if verify {
			projectCreators, isVerified, verificationErr := verifyLokaliseKey(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
			if len(projectCreators) > 0 {
				s1.ExtraData["project creators"] = strings.Join(projectCreators, ", ")
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

type projectsResponse struct {
	Projects []struct {
		CreatedByEmail string `json:"created_by_email"`
	} `json:"projects"`
}

func verifyLokaliseKey(ctx context.Context, client *http.Client, token string) ([]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.lokalise.com/api2/projects", http.NoBody)
	if err != nil {
		return nil, false, err
	}

	req.Header.Add("X-Api-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var projectCreators projectsResponse
		var creatorsList = make([]string, 0)

		if err := json.NewDecoder(resp.Body).Decode(&projectCreators); err != nil {
			// if failed to decode in case of 200 OK - return true without list
			return nil, true, nil
		}

		for _, project := range projectCreators.Projects {
			creatorsList = append(creatorsList, project.CreatedByEmail)
		}

		return creatorsList, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
