package jdbc

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kylelemons/godebug/pretty"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestJdbc_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			// examples from: https://github.com/trufflesecurity/trufflehog/issues/3704
			name: "valid patterns",
			input: `
				<?xml version="1.0" encoding="UTF-8"?>
					<project version="4">
						<component name="DataSourceManagerImpl" format="xml" multifile-model="true">
							<data-source source="LOCAL" name="PostgreSQL - postgres@localhost" uuid="18f0f64d-b804-471d-9351-e98a67c8389f">
							<driver-ref>postgresql</driver-ref>
							<synchronize>true</synchronize>
							<jdbc-driver>org.postgresql.Driver</jdbc-driver>
							<jdbc-url>jdbc:postgresql://localhost:5432/postgres</jdbc-url>
							<jdbc-url>jdbc:sqlserver:</jdbc-url>
							<jdbc-url>jdbc:postgresql://#{uri.host}#{uri.path}?user=#{uri.user}</jdbc-url>
							<jdbc-url>postgresql://postgres:postgres@<your-connection-ip-address>:5432</jdbc-url>
							<jdbc-url>jdbc:mysql:localhost:3306/mydatabase</jdbc-url>
							<jdbc-url>jdbc:sqlserver://x.x.x.x:1433;databaseName=MY-DB;user=MY-USER;password=MY-PASSWORD;encrypt=false</jdbc-url>
							<jdbc-url>jdbc:sqlserver://localhost:1433;databaseName=AdventureWorks</jdbc-url>
							<working-dir>$ProjectFileDir$</working-dir>
							</data-source>
						</component>
					</project>
			`,
			want: []string{
				"jdbc:postgresql://localhost:5432/postgres",
				"jdbc:mysql:localhost:3306/mydatabase",
				"jdbc:sqlserver://x.x.x.x:1433;databaseName=MY-DB;user=MY-USER;password=MY-PASSWORD;encrypt=false",
				"jdbc:sqlserver://localhost:1433;databaseName=AdventureWorks",
			},
		},
		{
			name: "valid pattern - true positives",
			input: `
				{
					"detector": "jdbc",
					"potential_matches": [
						"jdbc:postgresql://localhost:5432/mydb",
						"jdbc:mysql://user:pass@host:3306/db?param=1",
						"jdbc:sqlite:/data/test.db",
						"jdbc:oracle:thin:@host:1521:db",
						"jdbc:mysql://host:3306/db,other_param",
						"jdbc:db2://host:50000/db?param=1"
					]
				}`,
			want: []string{
				"jdbc:postgresql://localhost:5432/mydb",
				"jdbc:mysql://user:pass@host:3306/db?param=1",
				"jdbc:sqlite:/data/test.db",
				"jdbc:oracle:thin:@host:1521:db",
				"jdbc:mysql://host:3306/db",
				"jdbc:db2://host:50000/db?param=1",
			},
		},
		{
			name: "invalid pattern - false positives",
			input: `
				{
					"detector": "jdbc",
					"false_positives": [
						"jdbc:xyz:short",
						"somejdbc:mysql://host/db",
						"jdbc:invalid_driver:test",
						"jdbc:mysql://host/db>next",
						"adjdbc:mysql://host/db",
						"jdbc:my?ql:localhost:3306/my database"
					]
				}`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func TestJdbc_FromDataWithIgnorePattern(t *testing.T) {
	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name           string
		args           args
		want           []detectors.Result
		ignorePatterns []string
		wantErr        bool
	}{
		{
			name: "not found",
			args: args{
				ctx:    context.Background(),
				data:   []byte("jdbc:sqlite::secretpattern:"),
				verify: false,
			},
			want: nil,
			ignorePatterns: []string{
				".*secretpattern.*",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(WithIgnorePattern(tt.ignorePatterns))
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Jdbc.FromDataWithConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if os.Getenv("FORCE_PASS_DIFF") == "true" {
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Jdbc.FromDataWithConfig() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestParseSqlServerMissingCredentialsBug1(t *testing.T) {
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

			sqlServerConn := j.(*sqlServerJDBC)
			expectedPrefix := fmt.Sprintf("sqlserver://%s:", tt.wantUsername)

			if !strings.Contains(sqlServerConn.connStr, expectedPrefix) {
				t.Errorf("Connection string does not contain expected username '%s'\nGot: %s\nExpected to contain: %s",
					tt.wantUsername, sqlServerConn.connStr, expectedPrefix)
			}
		})
	}
}

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
				t.Fatalf("parsePostgres() error = %v", err)
			}

			pgConn := j.(*postgresJDBC)
			if pgConn.params["user"] != tt.wantUsername {
				t.Errorf("expected username '%s', got '%s'", tt.wantUsername, pgConn.params["user"])
			}
		})
	}
}

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
