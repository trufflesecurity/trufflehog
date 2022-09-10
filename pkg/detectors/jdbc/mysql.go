package jdbc

import (
	"errors"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

type mysqlJDBC struct {
	conn     string
	userPass string
	host     string
	database string
	params   string
}

func (s *mysqlJDBC) ping() bool {
	if ping("mysql", s.conn) {
		return true
	}
	// try building connection string (should be same as s.conn though)
	if ping("mysql", s.build()) {
		return true
	}
	// try removing database
	s.database = ""
	return ping("mysql", s.build())
}

func (s *mysqlJDBC) build() string {
	conn := s.host + "/" + s.database
	if s.userPass != "" {
		conn = s.userPass + "@" + conn
	}
	if s.params != "" {
		conn = conn + "?" + s.params
	}
	return conn
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
