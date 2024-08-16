package mysql

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

//go:embed expected_output.json
var expectedOutput []byte

func TestAnalyzer_Analyze(t *testing.T) {
	mysqlUser := "root"
	mysqlPass := gofakeit.Password(true, true, true, false, false, 10)
	mysqlDatabase := "mysql"

	ctx := context.Background()

	mysqlC, err := mysql.Run(ctx, "mysql",
		mysql.WithDatabase(mysqlDatabase),
		mysql.WithUsername(mysqlUser),
		mysql.WithPassword(mysqlPass),
	)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = mysqlC.Terminate(ctx) }()

	host, err := mysqlC.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := mysqlC.MappedPort(ctx, "3306")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		connectionString string
		want             []byte // JSON string
		wantErr          bool
	}{
		{
			name:             "valid Mysql connection",
			connectionString: fmt.Sprintf(`root:%s@%s:%s/%s`, mysqlPass, host, port.Port(), mysqlDatabase),
			want:             expectedOutput,
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{Cfg: &config.Config{}}
			got, err := a.Analyze(context.Background(), map[string]string{"connection_string": tt.connectionString})
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// bindings need to be in the same order to be comparable
			sortBindings(got.Bindings)

			// Marshal the actual result to JSON
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("could not marshal got to JSON: %s", err)
			}

			// Parse the expected JSON string
			var wantObj analyzers.AnalyzerResult
			if err := json.Unmarshal(tt.want, &wantObj); err != nil {
				t.Fatalf("could not unmarshal want JSON string: %s", err)
			}

			// bindings need to be in the same order to be comparable
			sortBindings(wantObj.Bindings)

			// Marshal the expected result to JSON (to normalize)
			wantJSON, err := json.Marshal(wantObj)
			if err != nil {
				t.Fatalf("could not marshal want to JSON: %s", err)
			}

			// Compare the JSON strings
			if string(gotJSON) != string(wantJSON) {
				// Pretty-print both JSON strings for easier comparison
				var gotIndented, wantIndented []byte
				gotIndented, err = json.MarshalIndent(got, "", " ")
				if err != nil {
					t.Fatalf("could not marshal got to indented JSON: %s", err)
				}
				wantIndented, err = json.MarshalIndent(wantObj, "", " ")
				if err != nil {
					t.Fatalf("could not marshal want to indented JSON: %s", err)
				}

				t.Errorf("Analyzer.Analyze() = %s, want %s", gotIndented, wantIndented)
			}
		})
	}
}

// Helper function to sort bindings
func sortBindings(bindings []analyzers.Binding) {
	sort.SliceStable(bindings, func(i, j int) bool {
		if bindings[i].Resource.Name == bindings[j].Resource.Name {
			return bindings[i].Permission.Value < bindings[j].Permission.Value
		}
		return bindings[i].Resource.Name < bindings[j].Resource.Name
	})
}
