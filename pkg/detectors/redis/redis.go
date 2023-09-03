package redis

import (
	"bytes"
	"context"
	"net/url"
	"regexp"

	"github.com/go-redis/redis"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\bredis://[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("redis")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		urlMatch := bytes.TrimSpace(match[0])
		password := bytes.TrimSpace(match[1])

		if bytes.Equal(password, []byte("*")) {
			continue
		}

		parsedURL, err := url.Parse(string(urlMatch))
		if err != nil {
			continue
		}
		if _, ok := parsedURL.User.Password(); !ok {
			continue
		}

		redact := bytes.Replace(urlMatch, password, []byte("********"), -1)

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Redis,
			Raw:          urlMatch,
			Redacted:     string(redact),
		}

		if verify {
			s.Verified = verifyRedis(ctx, parsedURL)
		}

		if !s.Verified && bytes.HasPrefix(password, []byte("$")) {
			continue
		}

		if !s.Verified && detectors.IsKnownFalsePositive(s.Raw, detectors.DefaultFalsePositives, false) {
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
