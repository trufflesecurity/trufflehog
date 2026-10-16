package sqlserver

import (
	"context"
	"testing"
)

func TestSqlServer_FromData_SkipsPlaceholderPasswords(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
	}{
		{
			name:      "dotnet string.Format template",
			input:     `Server={0};Database={3};User Id={1};Password={2};`,
			wantCount: 0,
		},
		{
			name:      "named placeholder tokens",
			input:     `Server={ServerName};Database={DbName};User Id={UserId};Password={Password};`,
			wantCount: 0,
		},
		{
			name:      "real credential is still reported",
			input:     `Server=db.internal.example.com;Database=payroll;User Id=sa;Password=P@ssw0rd!;`,
			wantCount: 1,
		},
		{
			name:      "password containing braces is still reported",
			input:     `Server=db.internal.example.com;Database=payroll;User Id=sa;Password=a{0}b;`,
			wantCount: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Scanner{}.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData() returned error: %v", err)
			}
			if len(got) != test.wantCount {
				t.Errorf("got %d results, want %d", len(got), test.wantCount)
			}
		})
	}
}
