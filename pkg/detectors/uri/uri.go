package uri

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/jlaffaye/ftp"

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
	keyPat = regexp.MustCompile(`\b[a-zA-Z]{1,10}:?\/\/[-.%\w{}]{1,50}:([-.%\S]{3,50})@[-.%\w\/:]+\b`)

	client = common.SaneHttpClient()
)

type proxyRes struct {
	Verified bool `json:"verified"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"http"}
}

func allowlistedProtos(scheme string) bool {
	allowlisted := []string{"http", "https", "redis", "ftp"}
	for _, s := range allowlisted {
		if s == scheme {
			return true
		}
	}
	return false
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

		// Skip findings where the password starts with a `$` - it's almost certainly a variable.
		if strings.HasPrefix(password, "$") {
			continue
		}

		// Skip findings where the password only has "*" characters, this is a redacted password
		if strings.Trim(password, "*") == "" {
			continue
		}

		parsedURL, err := url.Parse(urlMatch)
		if err != nil {
			continue
		}
		if _, ok := parsedURL.User.Password(); !ok {
			continue
		}
		if !allowlistedProtos(parsedURL.Scheme) {
			continue
		}

		redact := strings.TrimSpace(strings.Replace(urlMatch, password, strings.Repeat("*", len(password)), -1))

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_URI,
			Raw:          []byte(urlMatch),
			Redacted:     redact,
		}

		if verify {
			switch parsedURL.Scheme {
			case "http", "https":
				s.Verified = verifyURL(ctx, parsedURL)
			case "redis":
				s.Verified = verifyRedis(ctx, parsedURL)
			case "ftp":
				s.Verified = verifyFTP(ctx, parsedURL)
			default:
				continue
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, false) {
			continue
		}

		results = append(results, s)
	}

	return detectors.CleanResults(results), nil
}

func verifyFTP(ctx context.Context, u *url.URL) bool {
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":21"
	}

	c, err := ftp.Dial(host, ftp.DialWithTimeout(5*time.Second))
	if err != nil {
		return false
	}

	password, _ := u.User.Password()
	err = c.Login(u.User.Username(), password)

	return err == nil
}

func verifyRedis(ctx context.Context, u *url.URL) bool {
	opt, err := redis.ParseURL(u.String())
	if err != nil {
		return false
	}

	client := redis.NewClient(opt)

	status, err := client.Ping().Result()
	if err == nil && status == "PONG" {
		return true
	}

	return false
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
