package bitbucketapppassword

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
	// The following patterns cover the methods of authentication found here:
	// https://support.atlassian.com/bitbucket-cloud/docs/using-app-passwords/, as well as for other general cases.

	// Covers 'username:appPassword' pattern
	credentialPairPattern = regexp.MustCompile(`\b([A-Za-z0-9-_]{1,30}):ATBB[A-Za-z0-9_=.-]+[A-Z0-9]{8}\b`)
	// Covers assignment of username to variable
	usernameAssignmentPattern = regexp.MustCompile(`(?im)(?:user|usr)\S{0,40}?[:=\s]{1,3}[ '"=]?([a-zA-Z0-9-_]{1,30})\b`)
	// Covers 'https://username@bitbucket.org' pattern
	usernameUrlPattern = regexp.MustCompile(`https://([a-zA-Z0-9-_]{1,30})@bitbucket.org`)
	// Covers '("username", "password")' pattern, used for HTTP Basic Auth
	httpBasicAuthPattern = regexp.MustCompile(`"([a-zA-Z0-9-_]{1,30})",(?: )?"ATBB[A-Za-z0-9_=.-]+[A-Z0-9]{8}"`)

	usernamePatterns = []*regexp.Regexp{usernamePat1, usernamePat2, usernamePat3, usernamePat4}

	appPasswordPat = regexp.MustCompile(`\bATBB[A-Za-z0-9_=.-]+[A-Z0-9]{8}\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bitbucketapppassword", "ATBB"}
}

// FromData will find and optionally verify Bitbucket App Password secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var usernameMatches [][]string
	for _, pattern := range usernamePatterns {
		usernameMatches = append(usernameMatches, pattern.FindAllStringSubmatch(dataStr, -1)...)
	}
	appPasswordMatches := appPasswordPat.FindAllString(dataStr, -1)

	for _, usernameMatch := range usernameMatches {
		if len(usernameMatch) != 2 {
			continue
		}
		resUsernameMatch := strings.TrimSpace(usernameMatch[1])

		for _, resAppPasswordMatch := range appPasswordMatches {

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_BitbucketAppPassword,
				Raw:          []byte(fmt.Sprintf(`%s: %s`, resUsernameMatch, resAppPasswordMatch)),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.bitbucket.org/2.0/user", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/json")
				data := fmt.Sprintf("%s:%s", resUsernameMatch, resAppPasswordMatch)
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(data))))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					// Status 403 FORBIDDEN indicates a valid secret without valid scope
					if res.StatusCode >= 200 && res.StatusCode < 300 || res.StatusCode == 403 {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BitbucketAppPassword
}

func (s Scanner) Description() string {
	return "Bitbucket is a Git repository hosting service by Atlassian. Bitbucket App Passwords are used to authenticate to the Bitbucket API."
}
