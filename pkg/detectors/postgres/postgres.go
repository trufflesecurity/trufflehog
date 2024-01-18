package postgres

import (
	"context"
	"database/sql"
	"fmt"
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

type Scanner struct{}

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

		hostport, ok := params["host"]
		if !ok {
			continue
		}

		if port, ok := params["port"]; ok {
			hostport = hostport + ":" + port
		}

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Postgres,
			Raw:          []byte(hostport + user + password),
			RawV2:        []byte(hostport + user + password),
		}

		if verify {
			if timeout := getDeadlineInSeconds(ctx); timeout != 0 {
				params["connect_timeout"] = strconv.Itoa(timeout)
			}

			// We'd like the 'allow' mode but pq doesn't support it (https://github.com/lib/pq/issues/776)
			// To kludge it we first try with 'require' and then fall back to 'disable' if there's an SSL error
			params["sslmode"] = "require"
			isVerified, verificationErr := verifyPostgres(params)
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

func verifyPostgres(params map[string]string) (bool, error) {
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
	} else if strings.Contains(err.Error(), "SSL is not enabled on the server") {
		params["sslmode"] = "disable"
		return verifyPostgres(params)
	}

	return false, err
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Postgres
}
