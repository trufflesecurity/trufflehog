package jdbc

import (
	"errors"
	"fmt"
	"strings"

	_ "github.com/lib/pq"
)

type postgresJDBC struct {
	conn   string
	params map[string]string
}

func (s *postgresJDBC) ping() bool {
	// try the provided connection string directly
	if ping("postgres", s.conn) {
		return true
	}
	// try as a URL
	if ping("postgres", "postgres://"+s.conn) {
		return true
	}
	// build a connection string
	data := map[string]string{
		// default user
		"user": "postgres",
	}
	for key, val := range s.params {
		if key == "host" {
			if h, p, found := strings.Cut(val, ":"); found {
				data["host"] = h
				data["port"] = p
				continue
			}
		}
		data[key] = val
	}
	if ping("postgres", joinKeyValues(data)) {
		return true
	}
	if s.params["dbname"] != "" {
		delete(s.params, "dbname")
		return s.ping()
	}
	return false
}

func joinKeyValues(m map[string]string) string {
	var data []string
	for k, v := range m {
		if v == "" {
			continue
		}
		data = append(data, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(data, " ")
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
