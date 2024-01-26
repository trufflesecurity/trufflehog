package uri

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	allowKnownTestSites bool
	client              *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\b(?:https?:)?\/\/[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+\b`)

	defaultClient = common.SaneHttpClient()
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"http"}
}

// FromData will find and optionally verify URI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		if !s.allowKnownTestSites {
			if strings.Contains(match[0], "httpbin.org") {
				continue
			}
			if strings.Contains(match[0], "httpwatch.com") {
				continue
			}
		}

		urlMatch := match[0]
		password := match[1]

		// Skip findings where the password only has "*" characters, this is a redacted password
		// Also include the url encoded "*" characters: "%2A"
		if strings.Trim(password, "*") == "" || strings.Trim(password, "%2A") == "" {
			continue
		}

		parsedURL, err := url.Parse(urlMatch)
		if err != nil {
			continue
		}
		if _, ok := parsedURL.User.Password(); !ok {
			continue
		}

		rawURL, _ := url.Parse(urlMatch)
		rawURLStr := rawURL.String()
		// Removing the path causes possible deduplication issues if some paths have basic auth and some do not.
		rawURL.Path = ""

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_URI,
			Raw:          []byte(rawURL.String()),
			RawV2:        []byte(rawURLStr),
			Redacted:     detectors.RedactURL(*rawURL),
		}

		if verify {
			if s.client == nil {
				s.client = defaultClient
			}
			isVerified, verificationError := verifyURL(ctx, s.client, parsedURL)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationError, password)
		}

		if !s1.Verified {
			// Skip unverified findings where the password starts with a `$` - it's almost certainly a variable.
			if strings.HasPrefix(password, "$") {
				continue
			}
		}

		if !s1.Verified && !s.allowKnownTestSites && detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, false) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyURL(ctx context.Context, client *http.Client, u *url.URL) (bool, error) {
	// defuse most SSRF payloads
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""

	credentialedURL := u.String()

	u.User = nil
	nonCredentialedURL := u.String()

	req, err := http.NewRequest("GET", credentialedURL, nil)
	if err != nil {
		return false, err
	}
	req = req.WithContext(ctx)
	credentialedRes, err := client.Do(req)
	if err != nil {
		return false, err
	}
	credentialedRes.Body.Close()

	// If the credentialed URL returns a non 2XX code, we can assume it's a false positive.
	if credentialedRes.StatusCode < 200 || credentialedRes.StatusCode > 299 {
		return false, nil
	}

	time.Sleep(time.Millisecond * 10)

	req, err = http.NewRequest("GET", nonCredentialedURL, nil)
	if err != nil {
		return false, err
	}
	req = req.WithContext(ctx)
	nonCredentialedRes, err := client.Do(req)
	if err != nil {
		return false, err
	}
	nonCredentialedRes.Body.Close()

	// If the non-credentialed URL returns a non 400-428 code and basic auth header, we can assume it's verified now.
	if nonCredentialedRes.StatusCode >= 400 && nonCredentialedRes.StatusCode < 429 {
		if nonCredentialedRes.Header.Get("WWW-Authenticate") != "" {
			return true, nil
		}
	}

	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_URI
}
