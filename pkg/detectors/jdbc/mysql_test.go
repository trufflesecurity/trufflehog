package jdbc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestParseMySQLMissingCredentials(t *testing.T) {
	tests := []struct {
		name        string
		subname     string
		shouldBeNil bool
		reason      string
	}{
		{
			name:        "no password - should return nil",
			subname:     "//examplehost.net:3306/dbname?user=admin",
			shouldBeNil: true,
			reason:      "no password present",
		},
		{
			name:        "no password (tcp format) - should return nil",
			subname:     "//tcp(examplehost.net:3306)/dbname?user=admin",
			shouldBeNil: true,
			reason:      "no password present in tcp format",
		},
		{
			name:        "no host - should return nil",
			subname:     "///dbname?user=admin&password=secret123",
			shouldBeNil: true,
			reason:      "no host present",
		},
		{
			name:        "no host and no password - should return nil",
			subname:     "///dbname",
			shouldBeNil: true,
			reason:      "no host or password present",
		},
		{
			name:        "valid with host and password - should succeed",
			subname:     "//examplehost.net:3306/dbname?user=root&password=secret123",
			shouldBeNil: false,
		},
		{
			name:        "valid with tcp(host:port) format - should succeed",
			subname:     "//root:secret123@tcp(examplehost.net:3306)/dbname",
			shouldBeNil: false,
		},
		{
			name:        "valid with localhost - should succeed",
			subname:     "//localhost/dbname?user=root&password=secret123",
			shouldBeNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := logContext.AddLogger(context.Background())
			j, err := parseMySQL(ctx, tt.subname)

			if tt.shouldBeNil {
				if j != nil {
					t.Errorf("parseMySQL() expected nil (%s), got: %v", tt.reason, j)
				}
			} else {
				if j == nil {
					t.Errorf("parseMySQL() returned nil, expected valid connection. err = %v", err)
				}
				if err != nil {
					t.Errorf("parseMySQL() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestParseMySQLUsernameRecognition(t *testing.T) {
	tests := []struct {
		name         string
		subname      string
		wantUsername string
	}{
		{
			name:         "user parameter specified",
			subname:      "//localhost:3306/dbname?user=myuser&password=mypass",
			wantUsername: "myuser",
		},
		{
			name:         "no user specified - default root",
			subname:      "//localhost:3306/dbname?password=mypass",
			wantUsername: "root",
		},
		{
			name:         "user specified (tcp format)",
			subname:      "//myuser:secret123@tcp(localhost:3306)/dbname",
			wantUsername: "myuser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := logContext.AddLogger(context.Background())
			j, err := parseMySQL(ctx, tt.subname)
			if err != nil {
				t.Fatalf("parseMySQL() error = %v", err)
			}

			mysqlConn := j.(*MysqlJDBC)
			if mysqlConn.User != tt.wantUsername {
				t.Errorf("Connection string does not contain expected username '%s'\nGot: %s\nExpected: %s",
					tt.wantUsername, mysqlConn.User, tt.wantUsername)
			}
		})
	}
}

func TestMySQL_ParseJDBCURL(t *testing.T) {
	tests := []struct {
		name     string
		jdbcURL  string
		wantHost string
		wantDB   string
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{
			name:     "basic URL with all parts",
			jdbcURL:  "jdbc:mysql://root:password@localhost:3306/testdb",
			wantHost: "tcp(localhost:3306)",
			wantDB:   "testdb",
			wantUser: "root",
			wantPass: "password",
		},
		{
			name:     "URL with default port",
			jdbcURL:  "jdbc:mysql://user:pass@dbhost/mydb",
			wantHost: "tcp(dbhost)",
			wantDB:   "mydb",
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:     "URL with query params for credentials",
			jdbcURL:  "jdbc:mysql://dbhost:3307/testdb?user=admin&password=secret",
			wantHost: "tcp(dbhost:3307)",
			wantDB:   "testdb",
			wantUser: "admin",
			wantPass: "secret",
		},
		{
			name:    "invalid URL - missing jdbc:mysql prefix",
			jdbcURL: "postgresql://user:pass@localhost/db",
			wantErr: true,
		},
		{
			name:    "invalid URL - missing //",
			jdbcURL: "jdbc:mysql:user:pass@localhost/db",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jdbc, err := NewJDBC(logContext.Background(), tt.jdbcURL)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			info := jdbc.GetConnectionInfo()
			assert.Equal(t, tt.wantHost, info.Host)
			assert.Equal(t, tt.wantDB, info.Database)
			assert.Equal(t, tt.wantUser, info.User)
			assert.Equal(t, tt.wantPass, info.Password)
		})
	}
}

func TestMySQL_ParseJDBCURL_DSNAddressParsing(t *testing.T) {
	tests := []struct {
		name     string
		jdbcURL  string
		wantHost string
	}{
		{
			name:     "DSN format with explicit port",
			jdbcURL:  "jdbc:mysql://myuser:mypass@tcp(localhost:3307)/mydb",
			wantHost: "tcp(localhost:3307)",
		},
		{
			name:     "DSN format with default port",
			jdbcURL:  "jdbc:mysql://myuser:mypass@tcp(db.example.com:3306)/testdb",
			wantHost: "tcp(db.example.com:3306)",
		},
		{
			name:     "DSN format without port",
			jdbcURL:  "jdbc:mysql://myuser:mypass@tcp(myhost)/mydb",
			wantHost: "tcp(myhost:3306)",
		},
		{
			name:     "Simple host:port format",
			jdbcURL:  "jdbc:mysql://root:password@mysql.server.com:3308/database",
			wantHost: "tcp(mysql.server.com:3308)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jdbc, err := NewJDBC(logContext.Background(), tt.jdbcURL)
			require.NoError(t, err)
			info := jdbc.GetConnectionInfo()
			assert.Equal(t, tt.wantHost, info.Host)
		})
	}
}

func TestMySQL_BuildNativeConnectionString(t *testing.T) {
	tests := []struct {
		name     string
		info     *ConnectionInfo
		wantUser string
		wantPass string
		wantHost string
		wantDB   string
	}{
		{
			name: "basic connection",
			info: &ConnectionInfo{
				Host:     "localhost",
				Database: "testdb",
				User:     "root",
				Password: "secret",
			},
			wantUser: "root",
			wantPass: "secret",
			wantHost: "localhost",
			wantDB:   "testdb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mysqlJDBC := &MysqlJDBC{
				ConnectionInfo: *tt.info,
			}
			connStr := mysqlJDBC.BuildConnectionString()

			// MySQL format: [user[:password]@]tcp(host:port)/database?timeout=10s
			assert.Contains(t, connStr, tt.wantUser)
			assert.Contains(t, connStr, tt.wantPass)
			assert.Contains(t, connStr, tt.wantHost)
			assert.Contains(t, connStr, "/"+tt.wantDB)
		})
	}
}
