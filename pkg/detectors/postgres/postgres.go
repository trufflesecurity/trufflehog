package postgres

import (
	"context"
    "database/sql"
	"net/url"
	"regexp"
	"strings"
    "fmt"
    "time"

    "github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	// URI pattern for PostgreSQL connection string
	uriPat = regexp.MustCompile(`\b(?i)postgresql://[\S]+\b`)

	// Separate patterns for username, password, and hostname
    hostnamePat = regexp.MustCompile(`(?i)(?:host|server).{0,40}?(\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b)`)


	// You might want to customize these patterns based on common practices in your codebases
)

func (s Scanner) Keywords() []string {
	return []string{"postgres", "psql", "pghost"}
}

func verifyPostgres(pgURL *url.URL) error {
    // Extract the necessary components
    username := ""
    password := ""
    if pgURL.User != nil {
        username = pgURL.User.Username()
        password, _ = pgURL.User.Password()
    }
    hostname := pgURL.Hostname()

    // Handle custom port
    port := pgURL.Port()
    if port == "" {
        port = "5432" // Default PostgreSQL port
    }

    // Handle SSL mode
    sslmode := "disable" // Default to disable
    queryParams := pgURL.Query()
    if sslQuery, ok := queryParams["sslmode"]; ok && len(sslQuery) > 0 {
        sslmode = sslQuery[0]
    }

    // Construct the PostgreSQL connection string
    connStr := fmt.Sprintf("user=%s password=%s host=%s port=%s sslmode=%s", username, password, hostname, port, sslmode)

    // Open a connection to the database
    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return err
    }
    defer db.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
    defer cancel()


    // Try to establish a connection
    err = db.PingContext(ctx)
    if err != nil {
        return err
    }

    // If we reach here, the credentials are valid
    return nil
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Check for inline connection strings
	uriMatches := uriPat.FindAllString(dataStr, -1)
	for _, uri := range uriMatches {
		pgURL, err := url.Parse(uri)
		if err != nil {
			continue
		}

		// PostgreSQL URLs might not always have the userinfo (username:password) part
		if pgURL.User != nil {
			username := pgURL.User.Username()
			password, _ := pgURL.User.Password()
			hostname := pgURL.Hostname()
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Postgres,
				Raw:          []byte(strings.Join([]string{hostname, username, password}, "\t")),
			}
            if verify {
                verificationErr:= verifyPostgres(pgURL)
                s1.Verified = verificationErr == nil
            }
			results = append(results, s1)
		}
	}

	// Check for separate components
    usernameRegexState := common.UsernameRegexCheck("")
	usernameMatches := usernameRegexState.Matches(data)

	passwordRegexState := common.PasswordRegexCheck("") // No explicit character exclusions by Snowflake for passwords
	passwordMatches := passwordRegexState.Matches(data)
	hostnameMatches := hostnamePat.FindAllStringSubmatch(dataStr, -1)

    // Combine the separate components into potential credentials
    for _, username := range usernameMatches {
        if len(username) < 2 {
            continue
        }
        for _, hostname := range hostnameMatches {
            if len(hostname) < 2 {
                continue
            }
            result := false
            s1 := detectors.Result{
                DetectorType: detectorspb.DetectorType_Postgres,
            }
            for _, password := range passwordMatches {
                if len(password) < 2 {
                    continue
                }
                
                // Since we're combining these, we should probably also ensure that the total length does not exceed the 255 character limit for hostnames
                combinedLength := len(username) + len(password) + len(hostname[1])
                if combinedLength > 255 {
                    continue // Skip if the combined length is too long
                }
                s1.Raw = []byte(strings.Join([]string{hostname[1], username, password}, "\t"))
                result = true
                postgresURL := url.URL{
                    Scheme: "postgresql",
                    User:   url.UserPassword(username, password),
                    Host:   fmt.Sprintf("%s:%s", hostname[1], "5432"),
                }
                if verify {
                    verificationErr:= verifyPostgres(&postgresURL)
                    s1.Verified = verificationErr == nil
                    break
                }
            }
            if result {
                results = append(results, s1)
            }
        }
    }


	// Verification could be done here if necessary

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Postgres
}

