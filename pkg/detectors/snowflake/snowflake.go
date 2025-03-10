package snowflake

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode"

	_ "github.com/snowflakedb/gosnowflake"
	regexp "github.com/wasilibs/go-re2"

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
	accountIdentifierPat = regexp.MustCompile(detectors.PrefixRegex([]string{"account"}) + `\b([a-zA-Z]{7}-[0-9a-zA-Z-_]{1,255}(.privatelink)?)\b`)
	usernameExclusionPat = `!@#$%^&*{}:<>,.;?()/\+=\s\n`
)

const (
	database                  = "SNOWFLAKE"
	retrieveAllDatabasesQuery = "SHOW DATABASES"
	timeout                   = 3
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

	uniqueAccountMatches := make(map[string]struct{})
	for _, match := range accountIdentifierPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAccountMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	usernameRegexState := common.UsernameRegexCheck(usernameExclusionPat)
	usernameMatches := usernameRegexState.Matches(data)

	passwordRegexState := common.PasswordRegexCheck(" ") // No explicit character exclusions by Snowflake for passwords
	passwordMatches := passwordRegexState.Matches(data)

	for resAccountMatch := range uniqueAccountMatches {
		for _, resUsernameMatch := range usernameMatches {
			for _, resPasswordMatch := range passwordMatches {
				_, metPasswordRequirements := meetsSnowflakePasswordRequirements(resPasswordMatch)

				if !metPasswordRequirements {
					continue
				}

				// Override default timeout of 60 seconds to 3 seconds to prevent long scan times/improve performance.
				uri := fmt.Sprintf("%s:%s@%s/%s?loginTimeout=%d", resUsernameMatch, resPasswordMatch, resAccountMatch, database, timeout)

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Snowflake,
					Raw:          []byte(resPasswordMatch),
					ExtraData: map[string]string{
						"account":  resAccountMatch,
						"username": resUsernameMatch,
					},
				}

				if verify {
					// Open a connection to Snowflake
					db, err := sql.Open("snowflake", uri) // Needs the snowflake driver from gosnowflake
					if err != nil {
						return nil, err
					}
					defer db.Close()

					if ctx == nil {
						ctx = context.Background()
					}

					// Disable pool + retries to prevent flooding the server with failed login attempts.
					db.SetConnMaxLifetime(time.Second)
					db.SetMaxOpenConns(1)

					err = db.PingContext(ctx)
					if err != nil {
						if strings.Contains(err.Error(), "Incorrect username or password was specified") {
							s1.Verified = false
						} else {
							s1.SetVerificationError(err, resPasswordMatch)
						}
					} else {
						rows, err := db.Query(retrieveAllDatabasesQuery)
						if err != nil {
							s1.ExtraData["Snowflake Querying Error on a Valid Credential"] = fmt.Sprintf("unable to query Snowflake %+v", err)
							continue
						}
						defer rows.Close()

						var databases []string
						for rows.Next() {
							var name, createdOn, isDefault, isCurrent, origin, owner, comment, option, retentionTime, kind string
							err := rows.Scan(&createdOn, &name, &isDefault, &isCurrent, &origin, &owner, &comment, &option, &retentionTime, &kind)
							if err != nil {
								s1.ExtraData["Snowflake Querying Error on a Valid Credential"] = fmt.Sprintf("unable to finish querying Snowflake to enrich secret ExtraData %+v", err)
							}
							databases = append(databases, name)
						}
						s1.ExtraData["databases"] = strings.Join(databases, ", ")

						if s1.VerificationError() == nil {
							s1.Verified = true
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
	return detectorspb.DetectorType_Snowflake
}

func (s Scanner) Description() string {
	return "Snowflake is a cloud data platform that provides data warehousing, data lakes, data sharing, and data exchange capabilities. Snowflake credentials can be used to access and manipulate data stored in Snowflake."
}
