package jdbc

import (
	"context"
	"testing"

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
			j, err := ParsePostgres(ctx, tt.subname)

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
			j, err := ParsePostgres(ctx, tt.subname)
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
