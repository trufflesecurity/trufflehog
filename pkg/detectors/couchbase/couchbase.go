package couchbase

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/couchbase/gocb/v2"
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
	connectionStringPat = regexp.MustCompile(detectors.PrefixRegex([]string{"couchbase://", "couchbases://", "conn"}) + `\bcb\.[a-z0-9]+\.cloud\.couchbase\.com\b`)
	usernamePat         = regexp.MustCompile(`(?i)(?:user|usr)(?:.|[\n\r]){0,15}(\b[^:?()/\+=\n\s]{2,35}\b)`)
	passwordPat         = regexp.MustCompile(`(?i)(?:pass|pwd)(?:.|[\n\r]){0,15}(\b[^<>;.*&|£\n\s]{8,100}$)`)
)

func meetsCouchbasePasswordRequirements(password string) (string, bool) {
	var hasLower, hasUpper, hasNumber, hasSpecialChar bool
	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecialChar = true
		}

		if hasLower && hasUpper && hasNumber && hasSpecialChar {
			return password, true
		}
	}

	return "", false
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"couchbase://", "couchbases://"}
}

// FromData will find and optionally verify Couchbase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	connectionStringMatches := connectionStringPat.FindAllStringSubmatch(dataStr, -1)
	usernameMatches := usernamePat.FindAllStringSubmatch(dataStr, -1)
	passwordMatches := passwordPat.FindAllStringSubmatch(dataStr, -1)

	fmt.Printf("usernameMatches: %+v\n ", usernameMatches)
	fmt.Printf("passwordMatches: %+v\n", passwordMatches)
	fmt.Printf("connectionStringMatches: %+v\n", connectionStringMatches)

	for _, connectionStringMatch := range connectionStringMatches {
		resConnectionStringMatch := strings.TrimSpace(connectionStringMatch[0])
		fmt.Printf("resConnectionStringMatch: %+v\n", resConnectionStringMatch)

		for _, usernameMatch := range usernameMatches {
			fmt.Printf("len(usernameMatch): %+v\n", len(usernameMatch))
			fmt.Printf("usernameMatch: %+v\n", usernameMatch[1])

			splitUserNameMatches := strings.Split(usernameMatch[0], " ")

			resUsernameMatch := strings.TrimSpace(splitUserNameMatches[1])

			fmt.Printf("resUsernameMatch:%+v\n", resUsernameMatch)
			for _, passwordMatch := range passwordMatches {
				if len(passwordMatch) != 2 {
					continue
				}

				fmt.Printf("len(passwordMatch): %+v\n", len(passwordMatch))
				fmt.Printf("passwordMatch: %+v\n", passwordMatch)

				splitUserNameMatches := strings.Split(usernameMatch[0], " ")

				resUsernameMatch := strings.TrimSpace(splitUserNameMatches[1])

				resPasswordMatch := strings.TrimSpace(passwordMatch[1])
				fmt.Printf("resPasswordMatch: %+v\n", resPasswordMatch)

				_, metPasswordRequirements := meetsCouchbasePasswordRequirements(resPasswordMatch)
				fmt.Printf("metPasswordRequirements: %+v\n", metPasswordRequirements)
				if !metPasswordRequirements {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Couchbase,
					Raw:          []byte(fmt.Sprintf("%s:%s@%s", resUsernameMatch, resPasswordMatch, resConnectionStringMatch)),
				}

				if verify {

					options := gocb.ClusterOptions{
						Authenticator: gocb.PasswordAuthenticator{
							Username: resUsernameMatch,
							Password: resPasswordMatch,
						},
					}

					// Sets a pre-configured profile called "wan-development" to help avoid latency issues
					// when accessing Capella from a different Wide Area Network
					// or Availability Zone (e.g. your laptop).
					if err := options.ApplyProfile(gocb.ClusterConfigProfileWanDevelopment); err != nil {
						log.Fatal("apply profile err", err)
					}

					// Initialize the Connection
					cluster, err := gocb.Connect(resConnectionStringMatch, options)
					if err != nil {
						continue
					}

					// We'll ping the KV nodes in our cluster.
					pings, err := cluster.Ping(&gocb.PingOptions{
						Timeout: time.Second * 5,
					})

					for _, ping := range pings.Services {
						for _, pingEndpoint := range ping {
							if pingEndpoint.State == gocb.PingStateOk {
								s1.Verified = true
								break
							} else {
								// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
								if detectors.IsKnownFalsePositive(resPasswordMatch, detectors.DefaultFalsePositives, true) {
									continue
								}
							}
						}
					}
				}

				results = append(results, s1)
			}
		}
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Couchbase
}
