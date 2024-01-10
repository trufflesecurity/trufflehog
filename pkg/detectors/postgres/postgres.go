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
	usernamePattern                    = regexp.MustCompile(`(?im)(?:user|usr)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:'"\s]{4,40})`)
	passwordPattern                    = regexp.MustCompile(`(?im)(?:pass)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:'"\s]{4,40})`)
)

type Scanner struct{}

func (s Scanner) Keywords() []string {
	return []string{"postgres", "psql", "pghost"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	var pgURLs []url.URL
	pgURLs = append(pgURLs, findUriMatches(string(data)))
	pgURLs = append(pgURLs, findComponentMatches(verify, string(data))...)

	for _, pgURL := range pgURLs {
		if pgURL.User == nil {
			continue
		}
		username := pgURL.User.Username()
		password, _ := pgURL.User.Password()
		hostport := pgURL.Host
		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Postgres,
			Raw:          []byte(hostport + username + password),
			RawV2:        []byte(hostport + username + password),
		}

		if verify {
			timeoutInSeconds := getDeadlineInSeconds(ctx)
			isVerified, verificationErr := verifyPostgres(&pgURL, timeoutInSeconds)
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

func getDeadlineInSeconds(ctx context.Context) int {
	deadline, ok := ctx.Deadline()
	if !ok {
		// Context does not have a deadline
		return 0
	}

	duration := time.Until(deadline)
	return int(duration.Seconds())
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

// check if postgres is running
func postgresRunning(hostname, port string) bool {
	connStr := fmt.Sprintf("host=%s port=%s sslmode=disable", hostname, port)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false
	}
	defer db.Close()
	return true
}

func findComponentMatches(verify bool, dataStr string) []url.URL {
	usernameMatches := usernamePattern.FindAllStringSubmatch(dataStr, -1)
	passwordMatches := passwordPattern.FindAllStringSubmatch(dataStr, -1)
	hostnameMatches := hostnamePattern.FindAllStringSubmatch(dataStr, -1)
	portMatches := portPattern.FindAllStringSubmatch(dataStr, -1)

	var pgURLs []url.URL

	hosts := findHosts(verify, hostnameMatches, portMatches)

	for _, username := range dedupMatches(usernameMatches) {
		for _, password := range dedupMatches(passwordMatches) {
			for _, host := range hosts {
				hostname, port := strings.Split(host, ":")[0], strings.Split(host, ":")[1]
				if combinedLength := len(username) + len(password) + len(hostname); combinedLength > 255 {
					continue
				}
				postgresURL := url.URL{
					Scheme: "postgresql",
					User:   url.UserPassword(username, password),
					Host:   fmt.Sprintf("%s:%s", hostname, port),
				}
				pgURLs = append(pgURLs, postgresURL)
			}
		}
	}
	return pgURLs
}

// if verification is turned on, and we can confirm that postgres is running on at least one host,
// return only hosts where it's running. otherwise return all hosts.
func findHosts(verify bool, hostnameMatches, portMatches [][]string) []string {
	hostnames := dedupMatches(hostnameMatches)
	ports := dedupMatches(portMatches)
	var hosts []string

	if len(hostnames) < 1 {
		hostnames = append(hostnames, defaultHost)
	}

	if len(ports) < 1 {
		ports = append(ports, defaultPort)
	}

	for _, hostname := range hostnames {
		for _, port := range ports {
			hosts = append(hosts, fmt.Sprintf("%s:%s", hostname, port))
		}
	}

	if verify {
		var verifiedHosts []string
		for _, host := range hosts {
			parts := strings.Split(host, ":")
			hostname, port := parts[0], parts[1]
			if postgresRunning(hostname, port) {
				verifiedHosts = append(verifiedHosts, host)
			}
		}
		if len(verifiedHosts) > 0 {
			return verifiedHosts
		}
	}

	return hosts
}

// deduplicate matches in order to reduce the number of verification requests
func dedupMatches(matches [][]string) []string {
	setOfMatches := make(map[string]struct{})
	for _, match := range matches {
		if len(match) > 1 {
			setOfMatches[match[1]] = struct{}{}
		}
	}
	var results []string
	for match := range setOfMatches {
		results = append(results, match)
	}
	return results
}

func verifyPostgres(pgURL *url.URL, timeoutInSeconds int) (bool, error) {
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
	if timeoutInSeconds > 0 {
		connStr = fmt.Sprintf("%s connect_timeout=%d", connStr, timeoutInSeconds)
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			// inactive host
			return false, nil
		}
		return false, err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err == nil {
		return true, nil
	} else if strings.Contains(err.Error(), "password authentication failed") || // incorrect username or password
		strings.Contains(err.Error(), "connection refused") { // inactive host
		return false, nil
	}

	// if ssl is not enabled, manually fall-back to sslmode=disable
	if strings.Contains(err.Error(), "SSL is not enabled on the server") {
		pgURL.RawQuery = fmt.Sprintf("sslmode=%s", "disable")
		return verifyPostgres(pgURL, timeoutInSeconds)
	}
	return false, err
}

func determineSSLMode(pgURL *url.URL) string {
	// default ssl mode is "prefer" per https://www.postgresql.org/docs/current/libpq-ssl.html
	// but is currently not implemented in the driver per https://github.com/lib/pq/issues/1006
	// default for the driver is "require". ideally we would use "allow" but that is also not supported by the driver.
	sslmode := "require"
	if sslQuery, ok := pgURL.Query()["sslmode"]; ok && len(sslQuery) > 0 {
		sslmode = sslQuery[0]
	}
	return sslmode
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Postgres
}
