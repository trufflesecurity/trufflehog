package jdbc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"

	mssql "github.com/microsoft/go-mssqldb"
)

type SqlServerJDBC struct {
	ConnectionInfo
}

var _ JDBC = (*SqlServerJDBC)(nil)

func (s *SqlServerJDBC) ping(ctx context.Context) pingResult {
	return ping(ctx, "mssql", isSqlServerErrorDeterminate,
		buildSQLServerConnectionString(s.Host, s.User, s.Password, "master", map[string]string{"connection+timeout": "5"}))
}

func (s *SqlServerJDBC) GetDBType() DatabaseType {
	return SQLServer
}

func (s *SqlServerJDBC) GetConnectionInfo() *ConnectionInfo {
	return &s.ConnectionInfo
}

func (s *SqlServerJDBC) BuildConnectionString() string {
	return buildSQLServerConnectionString(s.Host, s.User, s.Password, s.Database, s.Params)
}

func isSqlServerErrorDeterminate(err error) bool {
	// Error numbers from https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors?view=sql-server-ver16
	var sqlErr mssql.Error
	if errors.As(err, &sqlErr) {
		switch sqlErr.Number {
		case 18456:
			// Login failed
			// This is a determinate failure iff we tried to use a real user
			return sqlErr.Message != "login error: Login failed for user ''."
		}
	}
	return false
}

func parseSqlServer(ctx logContext.Context, subname string) (JDBC, error) {
	if !strings.HasPrefix(subname, "//") {
		return nil, errors.New("expected connection to start with //")
	}
	conn := strings.TrimPrefix(subname, "//")

	port := "1433"
	user := "sa"
	database := "master"
	var password, host string
	params := make(map[string]string)

	for i, param := range strings.Split(conn, ";") {
		key, value, found := strings.Cut(param, "=")
		if !found && i == 0 {
			//  String connectionUrl = "jdbc:sqlserver://<server>:<port>;encrypt=true;databaseName=AdventureWorks;user=<user>;password=<password>";
			if split := strings.Split(param, ":"); len(split) > 1 {
				host = split[0]
				port = split[1]
			} else {
				host = param
			}
			continue
		}

		// incase there is a bridge between jdbc and odbc, and conn string looks like this odbc:server
		if split := strings.Split(key, ":"); len(split) > 1 {
			key = split[1]
		}

		switch strings.ToLower(key) {
		case "password", "spring.datasource.password", "pwd":
			password = value
		case "server":
			host = value
		case "port":
			port = value
		case "user", "uid", "user id", "userid":
			user = value
		case "database", "databasename":
			database = value
		default:
			params[key] = value
		}
	}

	if password == "" || host == "" {
		ctx.Logger().WithName("jdbc").
			V(2).
			Info("Skipping invalid SQL Server URL - no password or host found")
		return nil, fmt.Errorf("missing host or password in connection string")
	}

	return &SqlServerJDBC{
		ConnectionInfo: ConnectionInfo{
			Host:     host + ":" + port,
			User:     user,
			Password: password,
			Database: database,
			Params:   params,
		},
	}, nil
}

func buildSQLServerConnectionString(host, user, password, database string, params map[string]string) string {
	conn := fmt.Sprintf("sqlserver://%s:%s@%s?database=%s", user, password, host, database)
	if len(params) > 0 {
		for k, v := range params {
			conn += fmt.Sprintf("&%s=%s", k, v)
		}
	}
	return conn
}
