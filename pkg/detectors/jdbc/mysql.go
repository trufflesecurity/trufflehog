package jdbc

import (
	"context"
	"errors"
	"github.com/go-sql-driver/mysql"
	"strings"
)

type mysqlJDBC struct {
	conn     string
	userPass string
	host     string
	database string
	params   string
}

func (s *mysqlJDBC) ping(ctx context.Context) pingResult {
	return ping(ctx, "mysql", isMySQLErrorDeterminate,
		s.conn,
		buildMySQLConnectionString(s.host, s.database, s.userPass, s.params),
		buildMySQLConnectionString(s.host, "", s.userPass, s.params))
}

func buildMySQLConnectionString(host, database, userPass, params string) string {
	conn := host + "/" + database
	if userPass != "" {
		conn = userPass + "@" + conn
	}
	if params != "" {
		conn = conn + "?" + params
	}
	return conn
}

func isMySQLErrorDeterminate(err error) bool {
	// MySQL error numbers from https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html
	if mySQLErr, isMySQLErr := err.(*mysql.MySQLError); isMySQLErr {
		switch mySQLErr.Number {
		case 1044:
			// User access denied to a particular database
			return false // "Indeterminate" so that other connection variations will be tried
		case 1045:
			// User access denied
			return true
		}
	}

	return false
}

func parseMySQL(subname string) (jdbc, error) {
	// expected form: [subprotocol:]//[user:password@]HOST[/DB][?key=val[&key=val]]
	hostAndDB, params, _ := strings.Cut(subname, "?")
	if !strings.HasPrefix(hostAndDB, "//") {
		return nil, errors.New("expected host to start with //")
	}
	userPassAndHostAndDB := strings.TrimPrefix(hostAndDB, "//")
	userPass, hostAndDB, found := strings.Cut(userPassAndHostAndDB, "@")
	if !found {
		hostAndDB = userPass
		userPass = ""
	}
	host, database, found := strings.Cut(hostAndDB, "/")
	if !found {
		return nil, errors.New("expected host and database to be separated by /")
	}
	return &mysqlJDBC{
		conn:     subname[2:],
		userPass: userPass,
		host:     host,
		database: database,
		params:   params,
	}, nil
}
