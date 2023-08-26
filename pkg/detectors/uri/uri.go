package uri

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	allowKnownTestSites bool
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\b(?:https?:)?\/\/[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+\b`)

	client = common.SaneHttpClient()
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("http")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		// do not convert the match[0] into a string.

		if !s.allowKnownTestSites {
			if bytes.Contains(match[0], []byte("httpbin.org")) {
				continue
			}

			if bytes.Contains(match[0], []byte("httpwatch.com")) {
				continue
			}
		}

		password := match[1]
		if bytes.Trim(password, "*") == nil || bytes.Trim(password, "%2A") == nil {
			continue
		}

		parsedURL, err := url.Parse(string(match[0]))
		if err != nil {
			continue
		}
		if _, ok := parsedURL.User.Password(); !ok {
			continue
		}

		rawURL, _ := url.Parse(string(match[0]))

		rawURL.Path = ""

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_URI,
			Raw:          []byte(rawURL.String()),
			RawV2:        match[0],
			Redacted:     detectors.RedactURL(*rawURL),
		}

		if verify {
			s.Verified = verifyURL(ctx, parsedURL)
		}

		if bytes.HasPrefix(password, []byte("$")) {
			continue
		}

		if !s.Verified && detectors.IsKnownFalsePositive(s.Raw, detectors.DefaultFalsePositives, false) {
			continue
		}

		results = append(results, s)
	}

	return results, nil
}

func verifyURL(ctx context.Context, u *url.URL) bool {
	// defuse most SSRF payloads
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""

	credentialedURL := u.String()

	u.User = nil
	nonCredentialedURL := u.String()

	req, err := http.NewRequest("GET", credentialedURL, nil)
	if err != nil {
		return false
	}
	req = req.WithContext(ctx)
	credentialedRes, err := client.Do(req)
	if err != nil {
		return false
	}
	credentialedRes.Body.Close()

	// If the credentialed URL returns a non 2XX code, we can assume it's a false positive.
	if credentialedRes.StatusCode < 200 || credentialedRes.StatusCode > 299 {
		return false
	}

	time.Sleep(time.Millisecond * 10)

	req, err = http.NewRequest("GET", nonCredentialedURL, nil)
	if err != nil {
		return false
	}
	req = req.WithContext(ctx)
	nonCredentialedRes, err := client.Do(req)
	if err != nil {
		return false
	}
	nonCredentialedRes.Body.Close()

	// If the non-credentialed URL returns a non 400-428 code and basic auth header, we can assume it's verified now.
	if nonCredentialedRes.StatusCode >= 400 && nonCredentialedRes.StatusCode < 429 {
		if nonCredentialedRes.Header.Get("WWW-Authenticate") != "" {
			return true
		}
	}

	return false
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_URI
}
