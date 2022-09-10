package jdbc

import (
	"strings"

	_ "github.com/denisenkom/go-mssqldb"
)

type sqlServerJDBC struct {
	conn string
}

func (s *sqlServerJDBC) ping() bool {
	if ping("mssql", s.conn) {
		return true
	}
	// try URL format
	return ping("mssql", "sqlserver://"+s.conn)
}

func parseSqlServer(subname string) (jdbc, error) {
	// expected form: //[username:password@]host/instance[?key=val[&key=val]]
	return &sqlServerJDBC{strings.TrimPrefix(subname, "//")}, nil
}
