package snowflake

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/snowflakedb/gosnowflake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"log"
	"net/http"
	"regexp"
	"unicode"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	accountIdentifierPat = regexp.MustCompile(detectors.PrefixRegex([]string{"account"}) + `\b[a-zA-Z]{7}-[0-9a-zA-Z]{7}\b`)
	usernameExclusionPat = `!@#$%^&*{}:<>,.;?()/\+=\s\n`
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

	//usernameRegexState := common.UsernameRegexCheck("")
	//usernameMatches := usernameRegexState.Matches(data)
	//
	//passwordRegexState := common.PasswordRegexCheck("") // No explicit character exclusions by Snowflake for passwords
	//passwordMatches := passwordRegexState.Matches(data)

	config := &gosnowflake.Config{
		Account:  accountName,
		User:     username,
		Password: password,
		Database: database,
		//Schema:    schema,
	}
	uri := fmt.Sprintf("%s:%s@%s/%s", config.User, config.Password, config.Account, config.Database)
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

	fmt.Println("Connected to Snowflake!")

	query := "SHOW TABLES IN DATABASE " + database
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	fmt.Println("Tables in database:")
	for rows.Next() {
		var tableName string
		err := rows.Scan(&tableName)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(tableName)
	}

	//dataStr := string(data)
	//
	//matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	//
	//for _, match := range matches {
	//	if len(match) != 2 {
	//		continue
	//	}
	//	resMatch := strings.TrimSpace(match[1])
	//
	//	s1 := detectors.Result{
	//		DetectorType: detectorspb.DetectorType_Snowflake,
	//		Raw:          []byte(resMatch),
	//	}
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Snowflake
}
