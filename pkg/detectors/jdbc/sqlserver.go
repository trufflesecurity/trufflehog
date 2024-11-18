package jdbc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	mssql "github.com/microsoft/go-mssqldb"
)

type sqlServerJDBC struct {
	connStr string
}

func (s *sqlServerJDBC) ping(ctx context.Context) pingResult {
	return ping(ctx, "mssql", isSqlServerErrorDeterminate,
		s.connStr)
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

	return false
}

func parseSqlServer(subname string) (jdbc, error) {
	if !strings.HasPrefix(subname, "//") {
		return nil, errors.New("expected connection to start with //")
	}
	conn := strings.TrimPrefix(subname, "//")

	port := "1433"
	var password, host string

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

		switch strings.ToLower(key) {
		case "password":
			password = value
		case "spring.datasource.password":
			password = value
		case "server":
			host = value
		case "port":
			port = value
		}
	}
	return &sqlServerJDBC{
		connStr: fmt.Sprintf("sqlserver://sa:%s@%s:%s?database=master&connection+timeout=5", password, host, port),
	}, nil
}
