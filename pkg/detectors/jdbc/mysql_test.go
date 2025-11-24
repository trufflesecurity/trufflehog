package jdbc

import (
	"context"
	"strings"
	"testing"

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

			mysqlConn := j.(*mysqlJDBC)
			if !strings.Contains(mysqlConn.userPass, tt.wantUsername) {
				t.Errorf("Connection string does not contain expected username '%s'\nGot: %s\nExpected: %s",
					tt.wantUsername, mysqlConn.userPass, tt.wantUsername)
			}
		})
	}
}
