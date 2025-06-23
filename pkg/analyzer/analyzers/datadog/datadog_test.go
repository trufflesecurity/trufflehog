package datadog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

//go:embed expected_output.json
var expectedOutput []byte

func TestAnalyzer_Analyze(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	defer cancel()

	// Get API keys from GCP
	var apiKey, appKey string
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "analyzers1")
	if err != nil {
		t.Fatalf("Could not get test secrets from GCP: %s", err)
	}

	// Get the required credentials
	apiKey = testSecrets.MustGetField("DATADOG_API_KEY")
	appKey = testSecrets.MustGetField("DATADOG_APP_KEY")

	// Fail if credentials are not available
	if apiKey == "" || appKey == "" {
		t.Fatalf("Datadog credentials are required for this test")
	}

	tests := []struct {
		name    string
		apiKey  string
		appKey  string
		want    []byte // JSON string
		wantErr bool
	}{
		{
			name:    "valid datadog credentials",
			apiKey:  apiKey,
			appKey:  appKey,
			want:    expectedOutput,
			wantErr: false,
		},
		{
			name:    "invalid credentials",
			apiKey:  "invalid_api_key",
			appKey:  "invalid_app_key",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{Cfg: &config.Config{}}
			got, err := a.Analyze(ctx, map[string]string{"apiKey": tt.apiKey, "appKey": tt.appKey})

			if (err != nil) != tt.wantErr {
				t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Skip verification for error cases
			if tt.wantErr {
				return
			}

			// For valid cases, verify we got a result
			if got == nil {
				t.Errorf("Analyzer.Analyze() = nil, want non-nil")
				return
			}

			// Verify type is correct
			if got.AnalyzerType != analyzers.AnalyzerTypeDatadog {
				t.Errorf("Analyzer.Analyze() returned wrong analyzer type, got %d want %d",
					got.AnalyzerType, analyzers.AnalyzerTypeDatadog)
			}

			// Bindings need to be in the same order to be comparable
			sortBindings(got.Bindings)

			// Marshal the actual result to JSON
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("could not marshal got to JSON: %s", err)
			}

			fmt.Println(string(gotJSON))

			// Parse the expected JSON string
			var wantObj analyzers.AnalyzerResult
			if err := json.Unmarshal(tt.want, &wantObj); err != nil {
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
		if bindings[i].Resource.Name == bindings[j].Resource.Name {
			return bindings[i].Permission.Value < bindings[j].Permission.Value
		}
		return bindings[i].Resource.Name < bindings[j].Resource.Name
	})
}
