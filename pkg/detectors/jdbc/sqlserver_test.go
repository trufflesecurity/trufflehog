package jdbc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestParseSqlServerMissingCredentials(t *testing.T) {
	tests := []struct {
		name        string
		subname     string
		shouldBeNil bool
		reason      string
	}{
		{
			name:        "no password - should return nil (nothing to verify)",
			subname:     "//examplehost.net;databaseName=QRG1;sendStringParametersAsUnicode=false",
			shouldBeNil: true,
			reason:      "no password present",
		},
		{
			name:        "no host - should return nil (invalid connection)",
			subname:     "//;password=secret123",
			shouldBeNil: true,
			reason:      "no host present",
		},
		{
			name:        "no host and no password - should return nil",
			subname:     "//;databaseName=QRG1",
			shouldBeNil: true,
			reason:      "no host or password present",
		},
		{
			name:        "csm-1584-example",
			subname:     "//examplehost.net;databaseName=QRG1;sendStringParametersAsUnicode=false;loginTimeout=4;applicationName=pdal-cat-hierarchy-loader-v1;",
			shouldBeNil: true,
			reason:      "no password present",
		},
		{
			name:        "valid with both host and password - should succeed",
			subname:     "//examplehost.net;password=secret123",
			shouldBeNil: false,
		},
		{
			name:        "valid with host:port and password - should succeed",
			subname:     "//examplehost.net:1433;password=secret123",
			shouldBeNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := logContext.AddLogger(context.Background())

			j, err := parseSqlServer(ctx, tt.subname)

			if tt.shouldBeNil {
				if j != nil {
					t.Errorf("parseSqlServer() expected nil (%s), but got connection: %v",
						tt.reason, j)
				}
			} else {
				if j == nil {
					t.Errorf("parseSqlServer() returned nil, expected valid connection. err = %v", err)
				}
				if err != nil {
					t.Errorf("parseSqlServer() unexpected error = %v", err)
				}
			}
		})
	}
}

// This test demonstrates the username is ignored when parsing the JDBC URL. Instead the default username "sa" is always used.
func TestParseSqlServerUserIgnoredBug2(t *testing.T) {
	tests := []struct {
		name         string
		subname      string // the part after "jdbc:sqlserver:"
		wantUsername string
	}{
		{
			name:         "user parameter specified",
			subname:      "//localhost:1433;user=myuser;password=mypass",
			wantUsername: "myuser",
		},
		{
			name:         "user id parameter specified",
			subname:      "//localhost:1433;user id=admin;password=secret",
			wantUsername: "admin",
		},
		{
			name:         "no user specified - should default to sa",
			subname:      "//localhost:1433;password=mypass",
			wantUsername: "sa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := logContext.AddLogger(context.Background())

			j, err := parseSqlServer(ctx, tt.subname)
			if err != nil {
				t.Fatalf("parseSqlServer() error = %v", err)
			}

			sqlServerConn := j.(*SqlServerJDBC)

			if sqlServerConn.User != tt.wantUsername {
				t.Errorf("Connection string does not contain expected username '%s'\nGot: %s\nExpected to contain: %s",
					tt.wantUsername, sqlServerConn.User, tt.wantUsername)
			}
		})
	}
}

func TestParseSqlServerWithJdbcAndOdbcBridgeString(t *testing.T) {
	subname := "//odbc:server=localhost;port=1433;database=testdb;password=testpassword"

	wantHost := "localhost"
	wantPort := "1433"
	wantPassword := "testpassword"
	wantDatabase := "testdb"

	ctx := logContext.AddLogger(context.Background())

	j, err := ParseSqlServer(ctx, subname)
	if err != nil {
		t.Fatalf("parseSqlServer() error = %v", err)
	}

	if j == nil {
		t.Fatalf("parseSqlServer() returned nil, expected valid connection.")
	}

	sqlServerConn, ok := j.(*SqlServerJDBC)
	if !ok {
		t.Fatalf("parseSqlServer() returned unexpected type %T, expected *SqlServerJDBC", j)
	}

	if sqlServerConn.Host != wantHost+":"+wantPort {
		t.Errorf("Host mismatch. Got: %s, Want: %s", sqlServerConn.Host, wantHost+":"+wantPort)
	}

	if sqlServerConn.Password != wantPassword {
		t.Errorf("Password mismatch. Got: %s, Want: %s", sqlServerConn.Password, wantPassword)
	}

	if sqlServerConn.Database != wantDatabase {
		t.Errorf("Database mismatch. Got: %s, Want: %s", sqlServerConn.Database, wantDatabase)
	}
}
func TestSQLServerHandler_ParseJDBCURL(t *testing.T) {
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
			name:     "basic URL with semicolon params",
			jdbcURL:  "jdbc:sqlserver://localhost:1433;database=testdb;user=sa;password=Pass123",
			wantHost: "localhost:1433",
			wantDB:   "testdb",
			wantUser: "sa",
			wantPass: "Pass123",
		},
		{
			name:     "URL with default port and database",
			jdbcURL:  "jdbc:sqlserver://dbhost;user=testuser;password=secret",
			wantHost: "dbhost:1433",
			wantDB:   "master",
			wantUser: "testuser",
			wantPass: "secret",
		},
		{
			name:     "URL with port in host",
			jdbcURL:  "jdbc:sqlserver://server.example.com:1434;databaseName=mydb;userId=admin;pwd=admin123",
			wantHost: "server.example.com:1434",
			wantDB:   "mydb",
			wantUser: "admin",
			wantPass: "admin123",
		},
		{
			name:    "invalid URL - missing jdbc:sqlserver prefix",
			jdbcURL: "jdbc:mysql://localhost/db",
			wantErr: true,
		},
		{
			name:    "invalid URL - missing //",
			jdbcURL: "jdbc:sqlserver:localhost;database=test",
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

func TestSQLServerHandler_BuildNativeConnectionString(t *testing.T) {
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
				User:     "sa",
				Password: "Pass123",
			},
			wantUser: "sa",
			wantPass: "Pass123",
			wantHost: "localhost",
			wantDB:   "testdb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jdbc := &SqlServerJDBC{
				ConnectionInfo: *tt.info,
			}
			connStr := jdbc.BuildConnectionString()

			// SQL Server format: sqlserver://user:password@host:port?database=db&connection+timeout=10
			assert.Contains(t, connStr, tt.wantUser)
			assert.Contains(t, connStr, tt.wantPass)
			assert.Contains(t, connStr, tt.wantHost)
			assert.Contains(t, connStr, "database="+tt.wantDB)
		})
	}
}
