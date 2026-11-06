package sqlserver

import (
	"context"
	"testing"
)

func TestSQLServer_PasswordSpecialChars5501(t *testing.T) {
	s := Scanner{}
	tests := []struct {
		name     string
		password string
		wantRaw  string // empty means: expect no result
	}{
		{name: "dollar mid-string", password: `Ab$cdFakeOnly123`, wantRaw: `Ab$cdFakeOnly123`},
		{name: "backtick mid-string", password: "Ab`cdFakeOnly123", wantRaw: "Ab`cdFakeOnly123"},
		{name: "apostrophe mid-string", password: `Ab'cdFakeOnly123`, wantRaw: `Ab'cdFakeOnly123`},
		{name: "leading dollar", password: `$cdFakeOnly123`, wantRaw: `$cdFakeOnly123`},
		{name: "leading backtick", password: "`cdFakeOnly123", wantRaw: "`cdFakeOnly123"},
		{name: "placeholder paren form skipped", password: `$(DbPassword)`, wantRaw: ``},
		{name: "placeholder brace-dollar form skipped", password: `${PASSWORD}`, wantRaw: ``},
		{name: "placeholder bare env var skipped", password: `$PASSWORD`, wantRaw: ``},
		{name: "placeholder format token skipped", password: `{Password}`, wantRaw: ``},
		{name: "password merely containing braces still reported", password: `Pass{0}word`, wantRaw: `Pass{0}word`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := `Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=` + test.password + `;TrustServerCertificate=True`
			results, err := s.FromData(context.Background(), false, []byte(input))
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if test.wantRaw == "" {
				if len(results) != 0 {
					t.Fatalf("expected no results for placeholder password %q, got %d (Raw=%q)", test.password, len(results), string(results[0].Raw))
				}
				return
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result for password %q, got %d", test.password, len(results))
			}
			if got := string(results[0].Raw); got != test.wantRaw {
				t.Errorf("Raw = %q, want %q", got, test.wantRaw)
			}
		})
	}
}

func TestSQLServer_WrappedConnectionString5502(t *testing.T) {
	s := Scanner{}
	tests := []struct {
		name    string
		input   string
		wantRaw string // empty means: expect no result
	}{
		{
			name:    "apostrophe-wrapped password last no semicolon",
			input:   `'Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=abc'`,
			wantRaw: `abc`,
		},
		{
			name:    "backtick-wrapped password last no semicolon",
			input:   "`Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=abc`",
			wantRaw: `abc`,
		},
		{
			name:    "apostrophe-wrapped password not last",
			input:   `'Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=abc;TrustServerCertificate=True'`,
			wantRaw: `abc`,
		},
		{
			name:    "double-quote-wrapped password last no semicolon",
			input:   `"Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=abc"`,
			wantRaw: `abc`,
		},
		{
			name:    "apostrophe-wrapped with trailing semicolon inside wrapper",
			input:   `'Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=abc;'`,
			wantRaw: `abc`,
		},
		{
			name:    "unquoted password genuinely ending in apostrophe is kept",
			input:   `Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=ab'`,
			wantRaw: `ab'`,
		},
		{
			name:    "unquoted password genuinely ending in backtick is kept",
			input:   "Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=ab`",
			wantRaw: "ab`",
		},
		{
			name:    "wrapped password genuinely ending in wrapper loses exactly one",
			input:   `'Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=ab''`,
			wantRaw: `ab'`,
		},
		{
			name:    "mismatched wrappers are not stripped",
			input:   "`Server=TEST-SQL;Database=Demo;User Id=demo_user;Password=abc'",
			wantRaw: `abc'`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := s.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if test.wantRaw == "" {
				if len(results) != 0 {
					t.Fatalf("expected no results, got %d", len(results))
				}
				return
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if got := string(results[0].Raw); got != test.wantRaw {
				t.Errorf("Raw = %q, want %q", got, test.wantRaw)
			}
		})
	}
}
