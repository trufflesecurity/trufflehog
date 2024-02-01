package redis

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/url"
	"strings"

	"github.com/go-redis/redis"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat        = regexp.MustCompile(`\bredi[s]{1,2}://[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+\b`)
	azureRedisPat = regexp.MustCompile(`\b([\w\d.-]{1,100}\.redis\.cache\.windows\.net:6380),password=([^,]{44}),ssl=True,abortConnect=False\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"redis"}
}

// FromData will find and optionally verify URI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	azureMatches := azureRedisPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range azureMatches {
		host := match[1]
		password := match[2]
		urlMatch := fmt.Sprintf("rediss://:%s@%s", password, host)

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

		redact := strings.TrimSpace(strings.Replace(urlMatch, password, "*******", -1))

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Redis,
			Raw:          []byte(urlMatch),
			Redacted:     redact,
		}

		if verify {
			s.Verified = verifyRedis(ctx, parsedURL)
		}

		if !s.Verified {
			// Skip unverified findings where the password starts with a `$` - it's almost certainly a variable.
			if strings.HasPrefix(password, "$") {
				continue
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, false) {
			continue
		}

		results = append(results, s)
	}

	for _, match := range matches {
		urlMatch := match[0]
		password := match[1]

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

		redact := strings.TrimSpace(strings.Replace(urlMatch, password, "*******", -1))

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Redis,
			Raw:          []byte(urlMatch),
			Redacted:     redact,
		}

		if verify {
			s.Verified = verifyRedis(ctx, parsedURL)
		}

		if !s.Verified {
			// Skip unverified findings where the password starts with a `$` - it's almost certainly a variable.
			if strings.HasPrefix(password, "$") {
				continue
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, false) {
			continue
		}

		results = append(results, s)
	}

	return results, nil
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Redis
}
