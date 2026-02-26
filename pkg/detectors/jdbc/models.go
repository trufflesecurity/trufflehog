package jdbc

import (
	"context"
)

type DatabaseType int

const (
	Unknown DatabaseType = iota
	MySQL
	PostgreSQL
	SQLServer
)

func (dt DatabaseType) String() string {
	switch dt {
	case MySQL:
		return "mysql"
	case PostgreSQL:
		return "postgresql"
	case SQLServer:
		return "sqlserver"
	default:
		return "unknown"
	}
}

type pingResult struct {
	err         error
	determinate bool
}

// ConnectionInfo holds parsed connection information
type ConnectionInfo struct {
	Host     string // includes port if specified, e.g., "host:port"
	Database string
	User     string
	Password string
	Params   map[string]string
}

type jdbcPinger interface {
	ping(context.Context) pingResult
}

// public interfaces for analyzer
type JDBCParser interface {
	GetConnectionInfo() *ConnectionInfo
	GetDBType() DatabaseType
	BuildConnectionString() string
}
type JDBC interface {
	jdbcPinger
	JDBCParser
}
