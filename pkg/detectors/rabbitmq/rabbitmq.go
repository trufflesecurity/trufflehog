package rabbitmq

import (
	"context"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\b(?:amqp:)?\/\/[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"amqp"}
}

// FromData will find and optionally verify RabbitMQ secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

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

		redact := strings.TrimSpace(strings.Replace(parsedURL.String(), password, "********", -1))

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_RabbitMQ,
			Raw:          []byte(urlMatch),
			Redacted:     redact,
		}

		if verify {
			conn, err := amqp.Dial(urlMatch)
			if err == nil {
				s.Verified = true
			}
			if conn != nil {
				conn.Close()
			}
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RabbitMQ
}
