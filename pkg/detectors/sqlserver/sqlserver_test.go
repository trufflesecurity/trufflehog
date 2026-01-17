package sqlserver

import (
	"context"
	"testing"
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
