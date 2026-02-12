package rabbitmq

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\b(?:amqps?):\/\/[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"amqp"}
}

// FromData will find and optionally verify RabbitMQ secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueMatches = make(map[string]string)
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[matches[0]] = matches[1]
	}

	for urlMatch, password := range uniqueMatches {
		// Skip common test hosts.
		if strings.Contains(urlMatch, "127.0.0.1") ||
			strings.Contains(urlMatch, "localhost") ||
			strings.Contains(urlMatch, "contoso.com") ||
			strings.Contains(urlMatch, "example.com") {
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

		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_RabbitMQ,
			Raw:          []byte(urlMatch),
			Redacted:     strings.TrimSpace(strings.Replace(parsedURL.String(), password, "********", -1)),
		}

		if verify {
			isVerified, verificationErr := s.verify(urlMatch)
			r.Verified = isVerified
			if verificationErr != nil {
				r.SetVerificationError(verificationErr, urlMatch)
			}
		}

		if !r.Verified {
			// Skip unverified findings where the password starts with a `$` - it's almost certainly a variable.
			if strings.HasPrefix(password, "$") {
				continue
			}
		}

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) verify(url string) (bool, error) {
	// Add a timeout.
	// https://github.com/rabbitmq/amqp091-go/blob/dc67c21576c230f589636319f05b7262915313e6/examples_test.go#L22
	conn, err := amqp.DialConfig(url, amqp.Config{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 10*time.Second)
		},
	})
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if err == nil {
		return true, nil
	}
	// Check if this is a determinate authentication failure
	errStr := strings.ToLower(err.Error())

	if (strings.Contains(errStr, "403") &&
		strings.Contains(errStr, "access_refused")) ||
		strings.Contains(errStr, "username or password not allowed") {
		return false, err
	}
	return false, err
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RabbitMQ
}

func (s Scanner) Description() string {
	return "RabbitMQ is an open-source message broker software that originally implemented the Advanced Message Queuing Protocol (AMQP). RabbitMQ credentials can be used to access and manage message queues."
}
