package jdbc

import (
	"context"
	"errors"
	"strings"

	_ "github.com/denisenkom/go-mssqldb"
)

type sqlServerJDBC struct {
	conn   string
	params map[string]string
}

func (s *sqlServerJDBC) ping(ctx context.Context) bool {
	if ping(ctx, "mssql", s.conn) {
		return true
	}
	if ping(ctx, "mssql", joinKeyValues(s.params, ";")) {
		return true
	}
	// try URL format
	return ping(ctx, "mssql", "sqlserver://"+s.conn)
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
