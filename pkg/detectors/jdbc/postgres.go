package jdbc

import (
	"context"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"strings"

	_ "github.com/lib/pq"
)

type postgresJDBC struct {
	conn   string
	params map[string]string
}

func (s *postgresJDBC) ping(ctx context.Context) pingResult {
	// It is crucial that we try to build a connection string ourselves before using the one we found. This is because
	// if the found connection string doesn't include a username, the driver will attempt to connect using the current
	// user's name, which will fail in a way that looks like a determinate failure, thus terminating the waterfall. In
	// contrast, when we build a connection string ourselves, if there's no username, we try 'postgres' instead, which
	// actually has a chance of working.
	return ping(ctx, "postgres", isPostgresErrorDeterminate,
		buildPostgresConnectionString(s.params, true),
		buildPostgresConnectionString(s.params, false),
		s.conn,
		"postgres://"+s.conn)
}

func isPostgresErrorDeterminate(err error) bool {
	// Postgres codes from https://www.postgresql.org/docs/current/errcodes-appendix.html
	if pqErr, isPostgresError := err.(*pq.Error); isPostgresError {
		switch pqErr.Code {
		case "28P01":
			// Invalid username/password
			return true
		case "3D000":
			// Unknown database
			return false // "Indeterminate" so that other connection variations will be tried
		case "3F000":
			// Unknown schema
			return false // "Indeterminate" so that other connection variations will be tried
		}
	}

	// For most detectors, if we don't know exactly what the problem is, we should return "determinate" in order to
	// mimic the two-state verification logic. But the JDBC detector is special: It tries multiple variations on a given
	// found secret in a waterfall, and returning "true" here terminates the waterfall. Therefore, it is safer to return
	// false by default so that we don't incorrectly terminate before we find a valid variation. This catch-all also
	// handles cases like network errors.
	return false
}

func joinKeyValues(m map[string]string, sep string) string {
	var data []string
	for k, v := range m {
		if v == "" {
			continue
		}
		data = append(data, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(data, sep)
}

func parsePostgres(subname string) (jdbc, error) {
	// expected form: //HOST/DB?key=value&key=value
	hostAndDB, paramString, _ := strings.Cut(subname, "?")
	if !strings.HasPrefix(hostAndDB, "//") {
		return nil, errors.New("expected host to start with //")
	}
	hostAndDB = strings.TrimPrefix(hostAndDB, "//")
	host, database, _ := strings.Cut(hostAndDB, "/")

	params := map[string]string{
		"host":   host,
		"dbname": database,
	}
	for _, param := range strings.Split(paramString, "&") {
		key, val, _ := strings.Cut(param, "=")
		params[key] = val
	}

	return &postgresJDBC{subname[2:], params}, nil
}

func buildPostgresConnectionString(params map[string]string, includeDbName bool) string {
	data := map[string]string{
		// default user
		"user": "postgres",
	}
	for key, val := range params {
		if key == "host" {
			if h, p, found := strings.Cut(val, ":"); found {
				data["host"] = h
				data["port"] = p
				continue
			}
		}
		if key == "dbname" && !includeDbName {
			continue
		}
		data[key] = val
	}

	return joinKeyValues(data, " ")
}
