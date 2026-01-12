package jdbc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"

	"github.com/lib/pq"
)

type PostgresJDBC struct {
	ConnectionInfo
}

var _ JDBC = (*PostgresJDBC)(nil)

func (s *PostgresJDBC) ping(ctx context.Context) pingResult {
	// It is crucial that we try to build a connection string ourselves before using the one we found. This is because
	// if the found connection string doesn't include a username, the driver will attempt to connect using the current
	// user's name, which will fail in a way that looks like a determinate failure, thus terminating the waterfall. In
	// contrast, when we build a connection string ourselves, if there's no username, we try 'postgres' instead, which
	// actually has a chance of working.
	return ping(ctx, "postgres", isPostgresErrorDeterminate,
		buildPostgresConnectionString(s.Host, s.User, s.Password, "postgres", s.Params, true),
		buildPostgresConnectionString(s.Host, s.User, s.Password, "postgres", s.Params, false),
	)
}

func (s *PostgresJDBC) GetDBType() DatabaseType {
	return PostgreSQL
}

func (s *PostgresJDBC) GetConnectionInfo() *ConnectionInfo {
	return &s.ConnectionInfo
}

func (s *PostgresJDBC) BuildConnectionString() string {
	return buildPostgresConnectionString(s.Host, s.User, s.Password, s.Database, s.Params, true)
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

func parsePostgres(ctx logContext.Context, subname string) (JDBC, error) {
	// expected form: [subprotocol:]//[user:password@]HOST[/DB][?key=val[&key=val]]

	if !strings.HasPrefix(subname, "//") {
		return nil, errors.New("expected host to start with //")
	}

	u, err := url.Parse(subname)
	if err != nil {
		return nil, err
	}

	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" {
		dbName = "postgres"
	}

	params := map[string]string{
		"connect_timeout": "5",
	}

	postgresJDBC := &PostgresJDBC{
		ConnectionInfo: ConnectionInfo{
			Host:     u.Host,
			Database: dbName,
			Params:   params,
		},
	}

	if u.User != nil {
		postgresJDBC.User = u.User.Username()
		pass, set := u.User.Password()
		if set {
			postgresJDBC.Password = pass
		}
	}

	if v := u.Query()["sslmode"]; len(v) > 0 {
		switch v[0] {
		// https://www.postgresql.org/docs/current/libpq-ssl.html#LIBPQ-SSL-PROTECTION
		case "disable", "allow", "prefer",
			"require", "verify-ca", "verify-full":
			postgresJDBC.Params["sslmode"] = v[0]
		}
	}

	if v := u.Query().Get("user"); v != "" {
		postgresJDBC.User = v
	}

	if v := u.Query().Get("password"); v != "" {
		postgresJDBC.Password = v
	}

	if postgresJDBC.Host == "" || postgresJDBC.Password == "" {
		ctx.Logger().WithName("jdbc").
			V(2).
			Info("Skipping invalid Postgres URL - no password or host found")
		return nil, fmt.Errorf("missing host or password in connection string")
	}

	return postgresJDBC, nil
}

func buildPostgresConnectionString(host string, user string, password string, dbName string, params map[string]string, includeDbName bool) string {
	data := map[string]string{
		// default user
		"user":     "postgres",
		"password": password,
		"host":     host,
	}
	if user != "" {
		data["user"] = user
	}
	if h, p, ok := strings.Cut(host, ":"); ok {
		data["host"] = h
		data["port"] = p
	}
	for key, val := range params {
		data[key] = val
	}

	if includeDbName {
		data["dbname"] = "postgres"
		if dbName != "" {
			data["dbname"] = dbName
		}
	}

	connStr := joinKeyValues(data, " ")

	return connStr
}
