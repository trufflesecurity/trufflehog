package sqlserver

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/microsoft/go-mssqldb/msdsn"

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

func TestSqlServer_PreDialAddress(t *testing.T) {
	tests := []struct {
		name        string
		connStr     string
		wantAddress string
		wantOK      bool
	}{
		{
			name:        "server without port uses default port",
			connStr:     "Server=db01;Database=master;User ID=sa;Password=P@ssw0rd!;",
			wantAddress: "db01:1433",
			wantOK:      true,
		},
		{
			name:        "data source without port uses default port",
			connStr:     "Data Source=db01;Database=master;User ID=sa;Password=P@ssw0rd!;",
			wantAddress: "db01:1433",
			wantOK:      true,
		},
		{
			name:        "port in server value",
			connStr:     "Server=db01,1444;Database=master;User ID=sa;Password=P@ssw0rd!;",
			wantAddress: "db01:1444",
			wantOK:      true,
		},
		{
			name:        "port parameter",
			connStr:     "Server=db01;Port=1444;Database=master;User ID=sa;Password=P@ssw0rd!;",
			wantAddress: "db01:1444",
			wantOK:      true,
		},
		{
			name:    "named instance without port is resolved by the driver",
			connStr: `Server=db01\SALES;Database=master;User ID=sa;Password=P@ssw0rd!;`,
			wantOK:  false,
		},
		{
			name:        "named instance with port",
			connStr:     `Server=db01\SALES,1444;Database=master;User ID=sa;Password=P@ssw0rd!;`,
			wantAddress: "db01:1444",
			wantOK:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := msdsn.Parse(test.connStr)
			if err != nil {
				t.Fatalf("msdsn.Parse() error = %v", err)
			}

			address, ok := preDialAddress(config)
			if ok != test.wantOK || address != test.wantAddress {
				t.Errorf("preDialAddress() = (%q, %v), want (%q, %v)", address, ok, test.wantAddress, test.wantOK)
			}
		})
	}
}
