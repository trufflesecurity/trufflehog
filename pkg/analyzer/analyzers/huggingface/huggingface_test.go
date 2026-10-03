package huggingface

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestAnalyzer_Analyze(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	tests := []struct {
		name    string
		key     string
		want    string // JSON string
		wantErr bool
	}{
		{
			name: "valid Huggingface key",
			key:  testSecrets.MustGetField("HUGGINGFACE"),
			want: `{
				"AnalyzerType":6,
				"Bindings":[
				   {
					  "Resource":{
						 "Name":"zubairkhan/test",
						 "FullyQualifiedName": "huggingface.com/model/64d8220c0d879296892ab835",
						 "Type":"model",
						 "Metadata":{
							"private":false
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"Read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"zubairkhan/first_repo",
						 "FullyQualifiedName": "huggingface.com/model/64d82349a787c9bc7bbb2ab4",
						 "Type":"model",
						 "Metadata":{
							"private":true
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"Read",
						 "Parent":null
					  }
				   }
				],
				"UnboundedResources":null,
				"Metadata":{
				   "name":"Zubair Khan",
				   "token_name":"another_one",
				   "token_type":"read",
				   "username":"zubairkhan"
				}
			 }`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{Cfg: &config.Config{}}
			got, err := a.Analyze(ctx, map[string]string{"key": tt.key})
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

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

// Test_secretInfoToAnalyzerResult_FineGrainedUnboundedResources verifies that
// models outside the token's fine-grained permission scopes land in
// UnboundedResources rather than producing bindings with empty Permission.Value.
func Test_secretInfoToAnalyzerResult_FineGrainedUnboundedResources(t *testing.T) {
	info := &SecretInfo{
		Token: HFTokenJSON{
			Username: "testuser",
			Name:     "Test User",
			Auth: struct {
				AccessToken struct {
					Name        string `json:"displayName"`
					Type        string `json:"role"`
					CreatedAt   string `json:"createdAt"`
					FineGrained struct {
						Global []string `json:"global"`
						Scoped []struct {
							Entity struct {
								Type string `json:"type"`
								Name string `json:"name"`
								ID   string `json:"_id"`
							} `json:"entity"`
							Permissions []string `json:"permissions"`
						} `json:"scoped"`
					} `json:"fineGrained"`
				}
			}{
				AccessToken: struct {
					Name        string `json:"displayName"`
					Type        string `json:"role"`
					CreatedAt   string `json:"createdAt"`
					FineGrained struct {
						Global []string `json:"global"`
						Scoped []struct {
							Entity struct {
								Type string `json:"type"`
								Name string `json:"name"`
								ID   string `json:"_id"`
							} `json:"entity"`
							Permissions []string `json:"permissions"`
						} `json:"scoped"`
					} `json:"fineGrained"`
				}{
					Name: "test-token",
					Type: FINEGRAINED,
					FineGrained: struct {
						Global []string `json:"global"`
						Scoped []struct {
							Entity struct {
								Type string `json:"type"`
								Name string `json:"name"`
								ID   string `json:"_id"`
							} `json:"entity"`
							Permissions []string `json:"permissions"`
						} `json:"scoped"`
					}{
						Scoped: []struct {
							Entity struct {
								Type string `json:"type"`
								Name string `json:"name"`
								ID   string `json:"_id"`
							} `json:"entity"`
							Permissions []string `json:"permissions"`
						}{
							{
								Entity: struct {
									Type string `json:"type"`
									Name string `json:"name"`
									ID   string `json:"_id"`
								}{Type: "user", Name: "testuser"},
								Permissions: []string{"repo.content.read"},
							},
						},
					},
				},
			},
		},
		Models: []Model{
			{Name: "testuser/scoped-model", ID: "abc123", Private: true},
			{Name: "other-org/unscoped-model", ID: "def456", Private: false},
			{Name: "another-org/also-unscoped", ID: "ghi789", Private: false},
		},
	}

	result := secretInfoToAnalyzerResult(info)

	// The scoped model should appear as a binding with a non-empty permission.
	if len(result.Bindings) == 0 {
		t.Fatal("expected at least one binding for the scoped model")
	}
	foundScoped := false
	for _, b := range result.Bindings {
		if b.Resource.Name == "testuser/scoped-model" {
			foundScoped = true
			if b.Permission.Value == "" {
				t.Error("scoped model binding has empty Permission.Value")
			}
		}
		if b.Permission.Value == "" {
			t.Errorf("binding for %q has empty Permission.Value (would fail proto validation)", b.Resource.Name)
		}
	}
	if !foundScoped {
		t.Error("expected testuser/scoped-model in Bindings")
	}

	// Unscoped models should appear in UnboundedResources, not Bindings.
	unscopedNames := map[string]bool{
		"other-org/unscoped-model":  false,
		"another-org/also-unscoped": false,
	}
	for _, r := range result.UnboundedResources {
		if _, want := unscopedNames[r.Name]; want {
			unscopedNames[r.Name] = true
		}
	}
	for name, found := range unscopedNames {
		if !found {
			t.Errorf("expected %q in UnboundedResources, but it was missing", name)
		}
	}

	// Verify unscoped models are NOT in Bindings.
	for _, b := range result.Bindings {
		if _, isUnscoped := unscopedNames[b.Resource.Name]; isUnscoped {
			t.Errorf("unscoped model %q should not appear in Bindings", b.Resource.Name)
		}
	}
}
