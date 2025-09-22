package couchbase

import (
	"context"
	"fmt"
	"time"
	"unicode"

	regexp "github.com/wasilibs/go-re2"

	"github.com/couchbase/gocb/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	connectionStringPat = regexp.MustCompile(`\b(cb\.[a-z0-9]+\.cloud\.couchbase\.com)\b`)
	usernamePat         = common.UsernameRegexCheck(`?()/\+=\s\n`)
	passwordPat         = common.PasswordRegexCheck(`^<>;.*&|£\n\s`)
)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Couchbase
}

func (s Scanner) Description() string {
	return "Couchbase is a distributed NoSQL cloud database. Couchbase credentials can be used to access and modify data within the Couchbase database."
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"couchbase://", "couchbases://"}
}

// FromData will find and optionally verify Couchbase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueConnStrings, uniqueUsernames, uniquePasswords = make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})

	for _, match := range connectionStringPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueConnStrings["couchbases://"+match[1]] = struct{}{}
	}

	for _, match := range usernamePat.Matches(data) {
		uniqueUsernames[match] = struct{}{}
	}

	for _, match := range passwordPat.Matches(data) {
		uniquePasswords[match] = struct{}{}
	}

	for connString := range uniqueConnStrings {
		for username := range uniqueUsernames {
			for password := range uniquePasswords {
				if !isValidCouchbasePassword(password) {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Couchbase,
					Raw:          fmt.Appendf([]byte(""), "%s:%s@%s", username, password, connString),
				}

				if verify {
					isVerified, verificationErr := verifyCouchBase(username, password, connString)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr)
					s1.SetPrimarySecretValue(connString)
				}

				results = append(results, s1)
			}
		}
	}
	return results, nil
}

func verifyCouchBase(username, password, connString string) (bool, error) {
	options := gocb.ClusterOptions{
		Authenticator: gocb.PasswordAuthenticator{
			Username: username,
			Password: password,
		},
	}

	// Sets a pre-configured profile called "wan-development" to help avoid latency issues
	// when accessing Capella from a different Wide Area Network
	// or Availability Zone (e.g. your laptop).
	if err := options.ApplyProfile(gocb.ClusterConfigProfileWanDevelopment); err != nil {
		return false, err
	}

	// Initialize the Connection
	cluster, err := gocb.Connect(connString, options)
	if err != nil {
		return false, err
	}

	// We'll ping the KV nodes in our cluster.
	pings, err := cluster.Ping(&gocb.PingOptions{
		Timeout: time.Second * 5,
	})

	if err != nil {
		return false, err
	}

	for _, ping := range pings.Services {
		for _, pingEndpoint := range ping {
			if pingEndpoint.State == gocb.PingStateOk {
				return true, nil
			}
		}
	}

	return false, nil
}

func isValidCouchbasePassword(password string) bool {
	var hasLower, hasUpper, hasNumber, hasSpecialChar bool

	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsNumber(r):
			hasNumber = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSpecialChar = true
		}
	}

	return hasLower && hasUpper && hasNumber && hasSpecialChar
}
