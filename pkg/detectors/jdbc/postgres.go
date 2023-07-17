package jdbc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	_ "github.com/lib/pq"
)

type postgresJDBC struct {
	conn   string
	params map[string]string
}

func (s *postgresJDBC) ping(ctx context.Context) bool {
	return ping(ctx, "postgres",
		s.conn,
		"postgres://"+s.conn,
		buildPostgresConnectionString(s.params, true),
		buildPostgresConnectionString(s.params, false))
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
