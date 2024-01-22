package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	defaultPort = "5432"
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
		user, ok := params["user"]
		if !ok {
			continue
		}

		password, ok := params["password"]
		if !ok {
			continue
		}

		host, ok := params["host"]
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

		port, ok := params["port"]
		if !ok {
			params["port"] = "5432"
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
		if requiressl := params["requiressl"]; requiressl == "0" {
			params["sslmode"] = "prefer"
		} else if requiressl == "1" {
			params["sslmode"] = "require"
		}

		if verify {
			// pq appears to ignore the context deadline, so we copy any timeout that's been set into the connection
			// parameters themselves.
			if timeout := getDeadlineInSeconds(ctx); timeout != 0 {
				params["connect_timeout"] = strconv.Itoa(timeout)
			}

			isVerified, verificationErr := verifyPostgres(params)
			result.Verified = isVerified
			result.SetVerificationError(verificationErr, password)
		}

		// We gather SSL information into ExtraData in case it's useful for later reporting.
		sslmode := params["sslmode"]
		if sslmode == "" {
			sslmode = "<unset>"
		}
		result.ExtraData = map[string]string{
			"sslmode": sslmode,
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

		params := make(map[string]string)
		parts := connStrPartPattern.FindAllStringSubmatch(connStr, -1)
		for _, part := range parts {
			params[part[1]] = part[2]
		}

		matches = append(matches, params)
	}
	return matches
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

func isErrorDatabaseNotFound(err error, dbName string) bool {
	if dbName == "" {
		dbName = "postgres"
	}
	missingDbErrorText := fmt.Sprintf("database \"%s\" does not exist", dbName)

	return strings.Contains(err.Error(), missingDbErrorText)
}

func verifyPostgres(params map[string]string) (bool, error) {
	if sslmode := params["sslmode"]; sslmode == "allow" || sslmode == "prefer" {
		// pq doesn't support 'allow' or 'prefer'. If we find either of them, we'll just ignore it. This will trigger
		// the same logic that is run if no sslmode is set at all (which mimics 'prefer', which is the default).
		delete(params, "sslmode")

		// We still want to save the original sslmode in ExtraData, so we'll re-add it before returning.
		defer func() {
			params["sslmode"] = sslmode
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
	if err == nil {
		return true, nil
	} else if strings.Contains(err.Error(), "password authentication failed") {
		return false, nil
	} else if errors.Is(err, pq.ErrSSLNotSupported) && params["sslmode"] == "" {
		// If the sslmode is unset, then either it was unset in the candidate secret, or we've intentionally unset it
		// because it was specified as 'allow' or 'prefer', neither of which pq supports. In all of these cases, non-SSL
		// connections are acceptable, so now we try a connection without SSL to see if it works.
		params["sslmode"] = "disable"
		defer delete(params, "sslmode") // We want to return with the original params map intact (for ExtraData)
		return verifyPostgres(params)
	} else if isErrorDatabaseNotFound(err, params["dbname"]) {
		return true, nil // If we know this, we were able to authenticate
	}

	return false, err
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Postgres
}
