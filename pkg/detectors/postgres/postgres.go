package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	defaultPort = "5432"

	pg_connect_timeout = "connect_timeout"
	pg_dbname          = "dbname"
	pg_host            = "host"
	pg_password        = "password"
	pg_port            = "port"
	pg_requiressl      = "requiressl"
	pg_sslmode         = "sslmode"
	pg_sslmode_allow   = "allow"
	pg_sslmode_disable = "disable"
	pg_sslmode_prefer  = "prefer"
	pg_sslmode_require = "require"
	pg_user            = "user"
)

// This detector currently only finds Postgres connection string URIs
// (https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-URIS) When it finds one, it uses
// pq.ParseURI to normalize this into space-separated key-value pair Postgres connection string, and then uses a regular
// expression to transform this connection string into a parameters map. This parameters map is manipulated prior to
// verification, which operates by transforming the map back into a space-separated kvp connection string. This is kind
// of clunky overall, but it has the benefit of preserving the connection string as a map when it needs to be modified,
// which is much nicer than having to patch a space-separated string of kvps.

// Multi-host connection string URIs are currently not supported because pq.ParseURI doesn't parse them correctly. If we
// happen to run into a case where this matters we can address it then.
var (
	_                  detectors.Detector = (*Scanner)(nil)
	uriPattern                            = regexp.MustCompile(`\b(?i)postgres(?:ql)?://\S+\b`)
	connStrPartPattern                    = regexp.MustCompile(`([[:alpha:]]+)='(.+?)' ?`)
)

type Scanner struct {
	detectLoopback bool // Automated tests run against localhost, but we want to ignore those results in the wild
}

func (s Scanner) Keywords() []string {
	return []string{"postgres"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	candidateParamSets := findUriMatches(data)

	for _, params := range candidateParamSets {
		if common.IsDone(ctx) {
			break
		}
		user, ok := params[pg_user]
		if !ok {
			continue
		}

		password, ok := params[pg_password]
		if !ok {
			continue
		}

		host, ok := params[pg_host]
		if !ok {
			continue
		}
		if !s.detectLoopback {
			if host == "localhost" {
				continue
			}
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				continue
			}
		}

		port, ok := params[pg_port]
		if !ok {
			port = defaultPort
			params[pg_port] = port
		}

		raw := []byte(fmt.Sprintf("postgresql://%s:%s@%s:%s", user, password, host, port))

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Postgres,
			Raw:          raw,
			RawV2:        raw,
		}

		// We don't need to normalize the (deprecated) requiressl option into the (up-to-date) sslmode option - pq can
		// do it for us - but we will do it anyway here so that when we later capture sslmode into ExtraData we will
		// capture it post-normalization. (The detector's behavior is undefined for candidate secrets that have both
		// requiressl and sslmode set.)
		if requiressl := params[pg_requiressl]; requiressl == "0" {
			params[pg_sslmode] = pg_sslmode_prefer
		} else if requiressl == "1" {
			params[pg_sslmode] = pg_sslmode_require
		}

		if verify {
			// pq appears to ignore the context deadline, so we copy any timeout that's been set into the connection
			// parameters themselves.
			if timeout, ok := getDeadlineInSeconds(ctx); ok && timeout > 0 {
				params[pg_connect_timeout] = strconv.Itoa(timeout)
			} else if timeout <= 0 {
				// Deadline in the context has already exceeded.
				break
			}

			isVerified, verificationErr := verifyPostgres(params)
			result.Verified = isVerified
			result.SetVerificationError(verificationErr, password)
		}

		// We gather SSL information into ExtraData in case it's useful for later reporting.
		sslmode := params[pg_sslmode]
		if sslmode == "" {
			sslmode = "<unset>"
		}
		result.ExtraData = map[string]string{
			pg_sslmode: sslmode,
		}

		if !result.Verified && detectors.IsKnownFalsePositive(password, detectors.DefaultFalsePositives, true) {
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

func findUriMatches(data []byte) []map[string]string {
	var matches []map[string]string
	for _, uri := range uriPattern.FindAll(data, -1) {
		connStr, err := pq.ParseURL(string(uri))
		if err != nil {
			continue
		}

		parts := connStrPartPattern.FindAllStringSubmatch(connStr, -1)
		params := make(map[string]string, len(parts))
		for _, part := range parts {
			params[part[1]] = part[2]
		}

		matches = append(matches, params)
	}
	return matches
}

// getDeadlineInSeconds gets the deadline from the context in seconds. If there
// is no deadline, false is returned. If the deadline is already exceeded, a
// negative or 0 value will be returned.
func getDeadlineInSeconds(ctx context.Context) (int, bool) {
	deadline, ok := ctx.Deadline()
	if !ok {
		// Context does not have a deadline.
		return 0, false
	}

	duration := time.Until(deadline)
	return int(duration.Seconds()), true
}

func isErrorDatabaseNotFound(err error, dbName string) bool {
	if dbName == "" {
		dbName = "postgres"
	}
	missingDbErrorText := fmt.Sprintf("database \"%s\" does not exist", dbName)

	return strings.Contains(err.Error(), missingDbErrorText)
}

func verifyPostgres(params map[string]string) (bool, error) {
	if sslmode := params[pg_sslmode]; sslmode == pg_sslmode_allow || sslmode == pg_sslmode_prefer {
		// pq doesn't support 'allow' or 'prefer'. If we find either of them, we'll just ignore it. This will trigger
		// the same logic that is run if no sslmode is set at all (which mimics 'prefer', which is the default).
		delete(params, pg_sslmode)

		// We still want to save the original sslmode in ExtraData, so we'll re-add it before returning.
		defer func() {
			params[pg_sslmode] = sslmode
		}()
	}

	var connStr string
	for key, value := range params {
		connStr += fmt.Sprintf("%s='%s'", key, value)
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	err = db.Ping()
	switch {
	case err == nil:
		return true, nil
	case strings.Contains(err.Error(), "password authentication failed"):
		return false, nil
	case errors.Is(err, pq.ErrSSLNotSupported) && params[pg_sslmode] == "":
		// If the sslmode is unset, then either it was unset in the candidate secret, or we've intentionally unset it
		// because it was specified as 'allow' or 'prefer', neither of which pq supports. In all of these cases, non-SSL
		// connections are acceptable, so now we try a connection without SSL.
		params[pg_sslmode] = pg_sslmode_disable
		defer delete(params, pg_sslmode) // We want to return with the original params map intact (for ExtraData)
		return verifyPostgres(params)
	case isErrorDatabaseNotFound(err, params[pg_dbname]):
		return true, nil // If we know this, we were able to authenticate
	default:
		return false, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Postgres
}
