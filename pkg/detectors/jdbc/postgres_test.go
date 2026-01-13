package jdbc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestParsePostgresMissingCredentials(t *testing.T) {
	tests := []struct {
		name        string
		subname     string
		shouldBeNil bool
		reason      string
	}{
		{
			name:        "no password - should return nil (nothing to verify)",
			subname:     "//examplehost.net:5432/dbname?user=admin",
			shouldBeNil: true,
			reason:      "no password present",
		},
		{
			name:        "no host - should return nil (invalid connection)",
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
			subname:     "//examplehost.net:5432/dbname?user=admin&password=secret123",
			shouldBeNil: false,
		},
		{
			name:        "valid with localhost and password - should succeed",
			subname:     "//localhost/dbname?user=postgres&password=secret123",
			shouldBeNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := logContext.AddLogger(context.Background())
			j, err := parsePostgres(ctx, tt.subname)

			if tt.shouldBeNil {
				if j != nil {
					t.Errorf("parsePostgres() expected nil (%s), got: %v", tt.reason, j)
				}
			} else {
				if j == nil {
					t.Errorf("parsePostgres() returned nil, expected valid connection. err = %v", err)
				}
				if err != nil {
					t.Errorf("parsePostgres() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestParsePostgresUsernameRecognition(t *testing.T) {
	tests := []struct {
		name         string
		subname      string
		wantUsername string
	}{
		{
			name:         "user parameter specified",
			subname:      "//localhost:5432/dbname?user=myuser&password=mypass",
			wantUsername: "myuser",
		},
		{
			name:         "user and password specified",
			subname:      "//myuser:mypassword@localhost:5432/dbname",
			wantUsername: "myuser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := logContext.AddLogger(context.Background())
			j, err := parsePostgres(ctx, tt.subname)
			if err != nil {
				t.Fatalf("ParsePostgres() error = %v", err)
			}

			pgConn := j.(*PostgresJDBC)
			if pgConn.User != tt.wantUsername {
				t.Errorf("expected username '%s', got '%s'", tt.wantUsername, pgConn.User)
			}
		})
	}
}

func TestPostgreSQLHandler_ParseJDBCURL(t *testing.T) {
	tests := []struct {
		name        string
		jdbcURL     string
		wantHost    string
		wantDB      string
		wantUser    string
		wantPass    string
		wantSSLMode string
		wantErr     bool
	}{
		{
			name:     "basic URL with all parts",
			jdbcURL:  "jdbc:postgresql://postgres:secret@localhost:5432/mydb",
			wantHost: "localhost:5432",
			wantDB:   "mydb",
			wantUser: "postgres",
			wantPass: "secret",
		},
		{
			name:     "URL with default port",
			jdbcURL:  "jdbc:postgresql://user:pass@dbhost/testdb",
			wantHost: "dbhost",
			wantDB:   "testdb",
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:     "URL with default database",
			jdbcURL:  "jdbc:postgresql://user:pass@dbhost:5433",
			wantHost: "dbhost:5433",
			wantDB:   "postgres",
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:        "URL with SSL mode",
			jdbcURL:     "jdbc:postgresql://user:pass@dbhost:5432/mydb?sslmode=require",
			wantHost:    "dbhost:5432",
			wantDB:      "mydb",
			wantUser:    "user",
			wantPass:    "pass",
			wantSSLMode: "require",
		},
		{
			name:    "invalid URL - missing jdbc:postgresql prefix",
			jdbcURL: "mysql://user:pass@localhost/db",
			wantErr: true,
		},
		{
			name:    "invalid URL - missing //",
			jdbcURL: "jdbc:postgresql:user:pass@localhost/db",
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

			if tt.wantSSLMode != "" {
				assert.Equal(t, tt.wantSSLMode, info.Params["sslmode"])
			}
		})
	}
}

func TestPostgreSQLHandler_BuildNativeConnectionString(t *testing.T) {
	tests := []struct {
		name string
		info *ConnectionInfo
		want map[string]string // key-value pairs that should be in the connection string
	}{
		{
			name: "basic connection",
			info: &ConnectionInfo{
				Host:     "localhost",
				Database: "testdb",
				User:     "postgres",
				Password: "secret",
				Params: map[string]string{
					"connect_timeout": "10",
				},
			},
			want: map[string]string{
				"host":            "localhost",
				"dbname":          "testdb",
				"user":            "postgres",
				"password":        "secret",
				"connect_timeout": "10",
			},
		},
		{
			name: "with SSL mode",
			info: &ConnectionInfo{
				Host:     "dbhost:5433",
				Database: "mydb",
				User:     "user",
				Password: "pass",
				Params:   map[string]string{"sslmode": "require"},
			},
			want: map[string]string{
				"host":     "dbhost",
				"port":     "5433",
				"dbname":   "mydb",
				"sslmode":  "require",
				"user":     "user",
				"password": "pass",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jdbc := &PostgresJDBC{
				ConnectionInfo: *tt.info,
			}

			connStr := jdbc.BuildConnectionString()
			// Verify all expected key-value pairs are in the connection string
			for key, expectedValue := range tt.want {
				expectedPair := key + "=" + expectedValue
				assert.Contains(t, connStr, expectedPair)
			}
		})
	}
}
