package snowflake

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/snowflakedb/gosnowflake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"log"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	accountIdentifierPat = regexp.MustCompile(detectors.PrefixRegex([]string{"account"}) + `\b([a-zA-Z]{7}-[0-9a-zA-Z]{7})\b`)
	usernameExclusionPat = `!@#$%^&*{}:<>,.;?()/\+=\s\n`
)

const (
	database                  = "SNOWFLAKE"
	retrieveAllDatabasesQuery = "SHOW DATABASES"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"snowflake"}
}

func meetsSnowflakePasswordRequirements(password string) (string, bool) {
	var hasLower, hasUpper, hasNumber, minLen bool

	if len(password) < 8 {
		minLen = false
	} else {
		minLen = true
	}

	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsNumber(char):
			hasNumber = true
		}

		if hasLower && hasUpper && hasNumber && minLen {
			return password, true
		}
	}

	return "", false
}

// FromData will find and optionally verify Snowflake secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	accountMatches := accountIdentifierPat.FindAllStringSubmatch(dataStr, -1)

	fmt.Println("accountMatches: ", accountMatches)
	regexPat := detectors.PrefixRegex([]string{"account"}) + `\b([a-zA-Z]{7}-[0-9a-zA-Z]{7})\b`
	fmt.Println("regexPat", regexPat)

	usernameRegexState := common.UsernameRegexCheck(usernameExclusionPat)
	usernameMatches := usernameRegexState.Matches(data)

	passwordRegexState := common.PasswordRegexCheck(" ") // No explicit character exclusions by Snowflake for passwords
	passwordMatches := passwordRegexState.Matches(data)

	for _, accountMatch := range accountMatches {
		fmt.Println("accountMatch: ", accountMatch)
		if len(accountMatch) != 2 {
			continue
		}
		resAccountMatch := strings.TrimSpace(accountMatch[1])

		for _, resUsernameMatch := range usernameMatches {

			for _, resPasswordMatch := range passwordMatches {
				_, metPasswordRequirements := meetsSnowflakePasswordRequirements(resPasswordMatch)

				if !metPasswordRequirements {
					continue
				}

				uri := fmt.Sprintf("%s:%s@%s/%s", resUsernameMatch, resPasswordMatch, resAccountMatch, database)

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Snowflake,
					Raw:          []byte(resPasswordMatch),
					ExtraData: map[string]string{
						"account":  resAccountMatch,
						"username": resUsernameMatch,
					},
				}

				if verify {
					config := &gosnowflake.Config{
						Account:  resAccountMatch,
						User:     resUsernameMatch,
						Password: resPasswordMatch,
						Database: database,
					}

					fmt.Println("config: ", config)
					// Open a connection to Snowflake
					db, err := sql.Open("snowflake", uri) // Needs the snowflake driver from gosnowflake
					if err != nil {
						log.Fatal(err)
					}
					defer db.Close()

					err = db.Ping()
					if err != nil {
						log.Fatal(err)
					}

					s1.Verified = true

					rows, err := db.Query(retrieveAllDatabasesQuery)
					if err != nil {
						log.Fatal(err)
					}
					defer rows.Close()

					var databases []string
					for rows.Next() {
						var name, createdOn, is_default, isCurrent, origin, owner, comment, option, retention_time, kind string
						err := rows.Scan(&createdOn, &name, &is_default, &isCurrent, &origin, &owner, &comment, &option, &retention_time, &kind)
						if err != nil {
							log.Fatal(err)
						}
						databases = append(databases, name)
					}
					fmt.Println(databases)
					s1.ExtraData["databases"] = strings.Join(databases, ", ")

				}

				results = append(results, s1)
			}
		}
	}
	return results, nil
}

//
//	if verify {
//		client := s.client
//		if client == nil {
//			client = defaultClient
//		}
//		req, err := http.NewRequestWithContext(ctx, "GET", "https://eth-mainnet.g.snowflake.com/v2/"+resMatch+"/getNFTs/?owner=vitalik.eth", nil)
//		if err != nil {
//			continue
//		}
//		res, err := client.Do(req)
//		if err == nil {
//			defer res.Body.Close()
//			if res.StatusCode >= 200 && res.StatusCode < 300 {
//				s1.Verified = true
//			} else if res.StatusCode == 401 {
//				// The secret is determinately not verified (nothing to do)
//			} else {
//				s1.VerificationError = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
//			}
//		} else {
//			s1.VerificationError = err
//		}
//	}
//
//	// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
//	if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
//		continue
//	}
//
//	results = append(results, s1)
//}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Snowflake
}
