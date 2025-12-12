package jdbc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"

	"github.com/go-sql-driver/mysql"
)

type MysqlJDBC struct {
	ConnectionInfo
}

func (s *MysqlJDBC) ping(ctx context.Context) pingResult {
	return ping(ctx, "mysql", isMySQLErrorDeterminate,
		BuildMySQLConnectionString(s.Host, "", s.User, s.Password, s.Params))
}

func BuildMySQLConnectionString(host, database, user, password string, params map[string]string) string {
	conn := host + "/" + database
	userPass := user
	if password != "" {
		userPass = userPass + ":" + password
	}
	if userPass != "" {
		conn = userPass + "@" + conn
	}
	if len(params) > 0 {
		var paramList []string
		for k, v := range params {
			paramList = append(paramList, fmt.Sprintf("%s=%s", k, v))
		}
		conn = conn + "?" + strings.Join(paramList, "&")
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

func ParseMySQL(ctx logContext.Context, subname string) (jdbc, error) {
	// expected form: [subprotocol:]//[user:password@]HOST[/DB][?key=val[&key=val]]
	if !strings.HasPrefix(subname, "//") {
		return nil, errors.New("expected host to start with //")
	}

	// need for hostnames that have tcp(host:port) format required by this database driver
	cfg, err := mysql.ParseDSN(strings.TrimPrefix(subname, "//"))
	if err != nil {
		// fall back to URI parsing
		return parseMySQLURI(ctx, subname)
	}

	if cfg.Addr == "" || cfg.Passwd == "" {
		ctx.Logger().WithName("jdbc").
			V(2).
			Info("Skipping invalid MySQL URL - no password or host found")
		return nil, fmt.Errorf("missing host or password in connection string")
	}
	return &MysqlJDBC{
		ConnectionInfo: ConnectionInfo{
			User:     cfg.User,
			Password: cfg.Passwd,
			Host:     fmt.Sprintf("tcp(%s)", cfg.Addr),
			Params:   map[string]string{"timeout": "5s"},
			Database: cfg.DBName,
		},
	}, nil
}

func parseMySQLURI(ctx logContext.Context, subname string) (jdbc, error) {

	// for standard URI format, which is all i've seen for JDBC
	u, err := url.Parse(subname)
	if err != nil {
		return nil, err
	}

	user := "root"
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	if v := u.Query().Get("user"); v != "" {
		user = v
	}
	if v := u.Query().Get("password"); v != "" {
		pass = v
	}

	if u.Host == "" || pass == "" {
		ctx.Logger().WithName("jdbc").
			V(2).
			Info("Skipping invalid MySQL URL - no password or host found")
		return nil, fmt.Errorf("missing host or password in connection string")
	}

	// Parse database name
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" {
		dbName = "mysql" // default DB
	}

	return &MysqlJDBC{
		ConnectionInfo: ConnectionInfo{
			User:     user,
			Password: pass,
			Host:     fmt.Sprintf("tcp(%s)", u.Host),
			Params:   map[string]string{"timeout": "5s"},
			Database: dbName,
		},
	}, nil

}
