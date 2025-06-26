package bitbucketapppassword

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// Scanner is a stateless struct that implements the detector interface.
type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"bitbucket", "ATBB"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BitbucketAppPassword
}

func (s Scanner) Description() string {
	return "Bitbucket is a Git repository hosting service by Atlassian. Bitbucket App Passwords are used to authenticate to the Bitbucket API."
}

const bitbucketAPIUserURL = "https://api.bitbucket.org/2.0/user"

var (
	defaultClient = common.SaneHttpClient()
)

var (
	// credentialPatterns uses named capture groups (?P<name>...) for readability and robustness.
	credentialPatterns = []*regexp.Regexp{
		// Explicitly define the boundary as (start of string) or (a non-username character).
		regexp.MustCompile(`(?:^|[^A-Za-z0-9-_])(?P<username>[A-Za-z0-9-_]{1,30}):(?P<password>ATBB[A-Za-z0-9_=.-]+)\b`),
		// Catches 'https://username:password@bitbucket.org' pattern
		regexp.MustCompile(`https://(?P<username>[A-Za-z0-9-_]{1,30}):(?P<password>ATBB[A-Za-z0-9_=.-]+)@bitbucket\.org`),
		// Catches '("username", "password")' pattern, used for HTTP Basic Auth
		regexp.MustCompile(`"(?P<username>[A-Za-z0-9-_]{1,30})",\s*"(?P<password>ATBB[A-Za-z0-9_=.-]+)"`),
	}
)

// FromData will find and optionally verify Bitbucket App Password secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)

	uniqueCredentials := make(map[string]string)

	for _, pattern := range credentialPatterns {
		for _, match := range pattern.FindAllStringSubmatch(dataStr, -1) {
			// Extract credentials using named capture groups for readability.
			namedMatches := make(map[string]string)
			for i, name := range pattern.SubexpNames() {
				if i != 0 && name != "" {
					namedMatches[name] = match[i]
				}
			}

			username := namedMatches["username"]
			password := namedMatches["password"]

			if username != "" && password != "" {
				uniqueCredentials[username] = password
			}
		}
	}

	var results []detectors.Result
	for username, password := range uniqueCredentials {
		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_BitbucketAppPassword,
			Raw:          fmt.Appendf(nil, "%s:%s", username, password),
		}
		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			var vErr error
			result.Verified, vErr = verifyCredential(ctx, client, username, password)
			if vErr != nil {
				result.SetVerificationError(vErr, username, password)
			}
		}
		results = append(results, result)
	}

	return results, nil
}

// verifyCredential checks if a given username and app password are valid by making a request to the Bitbucket API.
func verifyCredential(ctx context.Context, client *http.Client, username, password string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bitbucketAPIUserURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	auth := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%s:%s", username, password))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", auth))

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		// A 403 can indicate a valid credential with insufficient scope, which is still a finding.
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
