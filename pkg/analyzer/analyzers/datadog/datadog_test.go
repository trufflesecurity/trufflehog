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

//go:embed expected_output_apikey.json
var expectedOutputAPIKey []byte

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
		name     string
		apiKey   string
		appKey   string
		endpoint string
		want     []byte // JSON string
		wantErr  bool
	}{
		{
			name:    "valid datadog credentials",
			apiKey:  apiKey,
			appKey:  appKey,
			want:    expectedOutput,
			wantErr: false,
		},
		{
			name:     "valid datadog credentials with endpoint",
			apiKey:   apiKey,
			appKey:   appKey,
			endpoint: "https://api.us5.datadoghq.com",
			want:     expectedOutput,
			wantErr:  false,
		},
		{
			name:     "valid datadog credentials with invalid endpoint",
			apiKey:   apiKey,
			appKey:   appKey,
			endpoint: "https://api.eu.datadoghq.com",
			want: []byte(fmt.Sprintf(`{
				"AnalyzerType": %d,
				"Bindings": [],
				"UnboundedResources": null,
				"Metadata": {}
			}`, analyzers.AnalyzerTypeDatadog)),
			wantErr: true,
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
			got, err := a.Analyze(ctx, map[string]string{"api_key": tt.apiKey, "app_key": tt.appKey, "endpoint": tt.endpoint})

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

			// Bindings and resources need to be in the same order to be comparable
			sortBindings(got.Bindings)
			sortResources(got.UnboundedResources)

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

			// Bindings and resources need to be in the same order to be comparable
			sortBindings(wantObj.Bindings)
			sortResources(wantObj.UnboundedResources)

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

func TestAnalyzer_Analyze_ApiKeyOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	defer cancel()

	// Get API keys from GCP
	var apiKey string
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "analyzers1")
	if err != nil {
		t.Fatalf("Could not get test secrets from GCP: %s", err)
	}

	// Get the required credentials
	apiKey = testSecrets.MustGetField("DATADOG_API_KEY")

	// Fail if credentials are not available
	if apiKey == "" {
		t.Fatalf("Datadog credentials are required for this test")
	}
	want := expectedOutputAPIKey

	a := Analyzer{Cfg: &config.Config{}}
	got, err := a.Analyze(ctx, map[string]string{"api_key": apiKey, "endpoint": "https://api.us5.datadoghq.com"})
	if err != nil {
		t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, false)
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

	// Bindings and resources need to be in the same order to be comparable
	sortBindings(got.Bindings)
	sortResources(got.UnboundedResources)

	// Marshal the actual result to JSON
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("could not marshal got to JSON: %s", err)
	}

	// Parse the expected JSON string
	var wantObj analyzers.AnalyzerResult
	if err := json.Unmarshal(want, &wantObj); err != nil {
		t.Fatalf("could not unmarshal want JSON string: %s", err)
	}

	// Bindings and resources need to be in the same order to be comparable
	sortBindings(wantObj.Bindings)
	sortResources(wantObj.UnboundedResources)

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

// sortResources orders resources by name. Resources are collected
// concurrently, so their order in a live result isn't stable.
func sortResources(resources []analyzers.Resource) {
	sort.SliceStable(resources, func(i, j int) bool {
		return resources[i].Name < resources[j].Name
	})
}

// Test_secretInfoToAnalyzerResult_ResourcesAreUnbounded verifies that
// dashboards and monitors land in UnboundedResources rather than producing
// bindings with an empty Permission.Value, and that each one keeps the key's
// user as its parent when the user is known.
func Test_secretInfoToAnalyzerResult_ResourcesAreUnbounded(t *testing.T) {
	user := User{Id: "user-1", Name: "Test User", Email: "test@example.com"}
	permissions := []Permission{{Title: "Dashboards Read"}, {Title: "Monitors Read"}}
	resources := []Resource{
		{ID: "abc-def-ghi", Name: "My Dashboard", Type: ResourceTypeDashboard, MetaData: map[string]string{"URL": "/dashboard/abc-def-ghi"}},
		{ID: "12345", Name: "My Monitor", Type: ResourceTypeMonitor},
	}

	tests := []struct {
		name           string
		user           User
		wantBindingFQN string
		wantParentFQN  string
	}{
		{
			name:           "known user is the parent of permissions and resources",
			user:           user,
			wantBindingFQN: "user-1",
			wantParentFQN:  "user-1",
		},
		{
			name:           "unknown user leaves resources without a parent",
			wantBindingFQN: "Unknown User",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := secretInfoToAnalyzerResult(&SecretInfo{
				User:        tt.user,
				Permissions: permissions,
				Resources:   resources,
			})

			if len(result.Bindings) != len(permissions) {
				t.Fatalf("got %d bindings, want one per permission (%d)", len(result.Bindings), len(permissions))
			}
			for _, b := range result.Bindings {
				if b.Permission.Value == "" {
					t.Errorf("binding for %q has empty Permission.Value (would fail proto validation)", b.Resource.Name)
				}
				if b.Resource.FullyQualifiedName != tt.wantBindingFQN {
					t.Errorf("binding for %q is bound to %q, want %q", b.Permission.Value, b.Resource.FullyQualifiedName, tt.wantBindingFQN)
				}
			}

			if len(result.UnboundedResources) != len(resources) {
				t.Fatalf("got %d unbounded resources, want %d", len(result.UnboundedResources), len(resources))
			}
			for i, r := range result.UnboundedResources {
				if r.FullyQualifiedName != resources[i].ID || r.Type != resources[i].Type {
					t.Errorf("unbounded resource %d = %q (%s), want %q (%s)", i, r.FullyQualifiedName, r.Type, resources[i].ID, resources[i].Type)
				}
				gotParentFQN := ""
				if r.Parent != nil {
					gotParentFQN = r.Parent.FullyQualifiedName
				}
				if gotParentFQN != tt.wantParentFQN {
					t.Errorf("unbounded resource %q has parent %q, want %q", r.Name, gotParentFQN, tt.wantParentFQN)
				}
			}
		})
	}
}

func Test_secretInfoToAnalyzerResult_NilInfo(t *testing.T) {
	if got := secretInfoToAnalyzerResult(nil); got != nil {
		t.Errorf("secretInfoToAnalyzerResult(nil) = %+v, want nil", got)
	}
}
