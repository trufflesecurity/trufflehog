package jdbc

import (
	"context"
	"errors"
	mssql "github.com/denisenkom/go-mssqldb"
	"strings"

	_ "github.com/denisenkom/go-mssqldb"
)

type sqlServerJDBC struct {
	conn   string
	params map[string]string
}

func (s *sqlServerJDBC) ping(ctx context.Context) pingResult {
	return ping(ctx, "mssql", isSqlServerErrorDeterminate,
		joinKeyValues(s.params, ";"),
		s.conn,
		"sqlserver://"+s.conn)
}

func isSqlServerErrorDeterminate(err error) bool {
	// Error numbers from https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors?view=sql-server-ver16
	if mssqlError, isMssqlError := err.(mssql.Error); isMssqlError {
		switch mssqlError.Number {
		case 18456:
			// Login failed
			// This is a determinate failure iff we tried to use a real user
			return mssqlError.Message != "login error: Login failed for user ''."
		}
	}

	// For most detectors, if we don't know exactly what the problem is, we should return "determinate" in order to
	// mimic the two-state verification logic. But the JDBC detector is special: It tries multiple variations on a given
	// found secret in a waterfall, and returning "true" here terminates the waterfall. Therefore, it is safer to return
	// false by default so that we don't incorrectly terminate before we find a valid variation. This catch-all also
	// handles cases like network errors.
	return false
}

func parseSqlServer(subname string) (jdbc, error) {
	if !strings.HasPrefix(subname, "//") {
		return nil, errors.New("expected connection to start with //")
	}
	conn := strings.TrimPrefix(subname, "//")
	params := map[string]string{
		"user id":  "sa",
		"database": "master",
	}
	for _, param := range strings.Split(conn, ";") {
		key, value, found := strings.Cut(param, "=")
		if !found {
			continue
		}
		params[key] = value
		if key != "password" && strings.Contains(strings.ToLower(key), "password") {
			params["password"] = value
		}
	}
	return &sqlServerJDBC{
		conn:   strings.TrimPrefix(subname, "//"),
		params: params,
	}, nil
}
