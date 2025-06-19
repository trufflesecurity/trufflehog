package jira

import (
	_ "embed"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

//go:embed result_output.json
var expectedOutput []byte

func TestAnalyzer_Analyze(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "analyzers1")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	jiraDomain := testSecrets.MustGetField("JIRA_DOMAIN_ANALYZE")
	jiraEmail := testSecrets.MustGetField("JIRA_EMAIL_ANALYZE")
	jiraToken := testSecrets.MustGetField("JIRA_TOKEN_ANALYZE")

	tests := []struct {
		name    string
		domain  string
		email   string
		token   string
		want    []byte
		wantErr bool
	}{
		{
			name:    "valid jira token",
			domain:  jiraDomain,
			email:   jiraEmail,
			token:   jiraToken,
			want:    expectedOutput,
			wantErr: false,
		},
		{
			name:    "invalid jira token",
			domain:  jiraDomain,
			email:   jiraEmail,
			token:   "invalid",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{Cfg: &config.Config{}}
			got, err := a.Analyze(ctx, map[string]string{"token": tt.token, "domain": tt.domain, "email": tt.email})
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if got != nil {
					t.Errorf("Analyzer.Analyze() got = %v, want nil", got)
				}
				return
			}

			// Bindings need to be in the same order to be comparable
			sortBindings(got.Bindings)

			// Marshal the actual result to JSON
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("could not marshal got to JSON: %s", err)
			}

			// Parse the expected JSON string
			var wantObj analyzers.AnalyzerResult
			if err := json.Unmarshal([]byte(tt.want), &wantObj); err != nil {
				t.Fatalf("could not unmarshal want JSON string: %s", err)
			}

			// Bindings need to be in the same order to be comparable
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
		if bindings[i].Resource.FullyQualifiedName == bindings[j].Resource.FullyQualifiedName {
			return bindings[i].Permission.Value < bindings[j].Permission.Value
		}
		return bindings[i].Resource.FullyQualifiedName < bindings[j].Resource.FullyQualifiedName
	})
}
