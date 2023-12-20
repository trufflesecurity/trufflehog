package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	defaultPort = "5432"
	defaultHost = "localhost"
)

var (
	_               detectors.Detector = (*Scanner)(nil)
	uriPattern                         = regexp.MustCompile(`\b(?i)postgresql://[\S]+\b`)
	hostnamePattern                    = regexp.MustCompile(`(?i)(?:host|server|address).{0,40}?(\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b)`)
	portPattern                        = regexp.MustCompile(`(?i)(?:port|p).{0,40}?(\b[0-9]{1,5}\b)`)
)

type Scanner struct{}

func (s Scanner) Keywords() []string {
	return []string{"postgres", "psql", "pghost"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	var pgURLs []url.URL
	pgURLs = append(pgURLs, findUriMatches(string(data)))
	pgURLs = append(pgURLs, findComponentMatches(string(data))...)

	for _, pgURL := range pgURLs {
		if pgURL.User == nil {
			continue
		}
		username := pgURL.User.Username()
		password, _ := pgURL.User.Password()
		hostport := pgURL.Host
		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Postgres,
			Raw:          []byte(username + password),
			RawV2:        []byte(hostport + username + password),
		}

		if verify {
			isVerified, verificationErr := verifyPostgres(&pgURL)
			result.Verified = isVerified
			result.SetVerificationError(verificationErr, password)
		}

		if !result.Verified && detectors.IsKnownFalsePositive(password, detectors.DefaultFalsePositives, true) {
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

func findUriMatches(dataStr string) url.URL {
	var pgURL url.URL
	for _, uri := range uriPattern.FindAllString(dataStr, -1) {
		pgURL, err := url.Parse(uri)
		if err != nil {
			continue
		}
		if pgURL.User != nil {
			return *pgURL
		}
	}
	return pgURL
}

func findComponentMatches(dataStr string) []url.URL {
	usernameMatches := common.UsernameRegexCheck("").Matches([]byte(dataStr))
	passwordMatches := common.PasswordRegexCheck("").Matches([]byte(dataStr))
	hostnameMatches := hostnamePattern.FindAllStringSubmatch(dataStr, -1)
	portMatches := portPattern.FindAllStringSubmatch(dataStr, -1)

	var pgURLs []url.URL

	for _, username := range usernameMatches {
		if len(username) < 2 {
			continue
		}
		for _, password := range passwordMatches {
			if len(password) < 2 {
				continue
			}
			for _, hostname := range hostnameMatches {
				if len(hostname) < 2 {
					continue
				}
				port := ""
				for _, ports := range portMatches {
					// this will only grab the last one if there are multiple
					// TODO @0x1: enumerate found ports first
					if len(ports) > 1 {
						port = ports[1]
					}
				}
				if combinedLength := len(username) + len(password) + len(hostname[1]); combinedLength > 255 {
					continue
				}
				postgresURL := url.URL{
					Scheme: "postgresql",
					User:   url.UserPassword(username, password),
					Host:   fmt.Sprintf("%s:%s", hostname[1], port),
				}
				pgURLs = append(pgURLs, postgresURL)
			}
		}
	}
	return pgURLs
}

func verifyPostgres(pgURL *url.URL) (bool, error) {
	if pgURL.User == nil {
		return false, nil
	}
	username := pgURL.User.Username()
	password, _ := pgURL.User.Password()

	hostname, port := pgURL.Hostname(), pgURL.Port()
	if hostname == "" {
		hostname = defaultHost
	}
	if port == "" {
		port = defaultPort
	}

	sslmode := determineSSLMode(pgURL)

	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%s sslmode=%s", username, password, hostname, port, sslmode)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err == nil {
		return true, nil
	} else if strings.Contains(err.Error(), "password authentication failed") {
		// incorrect username or password
		return false, nil
	}

	return false, err
}

func determineSSLMode(pgURL *url.URL) string {
	sslmode := "disable"
	if sslQuery, ok := pgURL.Query()["sslmode"]; ok && len(sslQuery) > 0 {
		sslmode = sslQuery[0]
	}
	return sslmode
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Postgres
}
