package sqlserver

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestSQLServer_Pattern(t *testing.T) {
	if !pattern.Match([]byte(`builder.Services.AddDbContext<Database>(optionsBuilder => optionsBuilder.UseSqlServer("Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;"));`)) {
		t.Errorf("SQLServer.pattern: did not find connection string from Program.cs")
	}
	if !pattern.Match([]byte(`{"ConnectionStrings": {"Demo": "Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;"}}`)) {
		t.Errorf("SQLServer.pattern: did not find connection string from appsettings.json")
	}
	if !pattern.Match([]byte(`CONNECTION_STRING: Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true`)) {
		t.Errorf("SQLServer.pattern: did not find connection string from .env")
	}
	if !pattern.Match([]byte(`<add name="Sample2" value="SERVER=server_name;DATABASE=database_name;user=user_name;pwd=plaintextpassword;encrypt=true;Timeout=120;MultipleActiveResultSets=True;" />`)) {
		t.Errorf("SQLServer.pattern: did not find connection string in xml format")
	}
}

const (
	validConnStr   = `builder.Services.AddDbContext<Database>(optionsBuilder => optionsBuilder.UseSqlServer("Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;"));`
	validParsedStr = `sqlserver://sa:P%40ssw0rd%21@localhost?database=master&dial+timeout=15&disableretry=false`
	invalidConnStr = `some random text without connection string`
)

func TestSqlServer_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword sql",
			input: fmt.Sprintf(`sql - %s`, validConnStr),
			want:  []string{validParsedStr},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("sql=%s", invalidConnStr),
			want:  []string{},
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

func TestSqlServer_ExtraData(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		wantHost     string
		wantUsername string
		wantDatabase string
	}{
		{
			name:         "server with explicit port",
			data:         `Server=localhost;Port=1433;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;`,
			wantHost:     "localhost:1433",
			wantUsername: "sa",
			wantDatabase: "master",
		},
		{
			name:         "server without port",
			data:         `Server=dbhost;Initial Catalog=mydb;User ID=admin;Password=secret123;`,
			wantHost:     "dbhost",
			wantUsername: "admin",
			wantDatabase: "mydb",
		},
		{
			name:         "xml style parameters",
			data:         `SERVER=server_name;DATABASE=testdb;user=username;password=badpassword;encrypt=true;`,
			wantHost:     "server_name",
			wantUsername: "username",
			wantDatabase: "testdb",
		},
		{
			name:         "no database specified",
			data:         `Server=localhost;Port=1433;User ID=sa;Password=123;`,
			wantHost:     "localhost:1433",
			wantUsername: "sa",
			wantDatabase: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			results, err := s.FromData(context.Background(), false, []byte(tt.data))
			require.NoError(t, err)
			require.NotEmpty(t, results, "expected at least one result")

			r := results[0]
			assert.Equal(t, tt.wantHost, r.ExtraData["host"])
			assert.Equal(t, tt.wantUsername, r.ExtraData["username"])
			assert.Equal(t, tt.wantDatabase, r.ExtraData["database"])
		})
	}
}

func TestSqlServer_FromDataWithIgnorePattern(t *testing.T) {
	s := New(
		WithIgnorePattern([]string{
			`^Server=localhost`,
		}))
	got, err := s.FromData(context.Background(), false, []byte("Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true"))
	if err != nil {
		t.Errorf("FromData() error = %v", err)
		return
	}
	if len(got) != 0 {
		t.Errorf("expected no results, but got %d", len(got))
	}
}
