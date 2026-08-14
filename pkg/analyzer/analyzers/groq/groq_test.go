package groq

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func resource(id, name, resourceType string) GroqResource {
	return GroqResource{
		ID:         id,
		Name:       name,
		Type:       resourceType,
		Permission: PermissionStrings[FullAccess],
		Metadata:   map[string]string{"status": "completed"},
	}
}

func TestSecretInfoToAnalyzerResult(t *testing.T) {
	tests := []struct {
		name      string
		resources []GroqResource
		wantLen   int
		wantNames []string 
		{
			name:      "one resource produces exactly one binding",
			resources: []GroqResource{resource("batch_123", "batch_123", "batch")},
			wantLen:   1,
			wantNames: []string{"batch_123"},
		},
		{
			name: "three resources produce exactly three bindings, not six",
			resources: []GroqResource{
				resource("batch_123", "batch_123", "batch"),
				resource("file_456", "training.jsonl", "file"),
				resource("file_789", "eval.jsonl", "file"),
			},
			wantLen:   3,
			wantNames: []string{"batch_123", "training.jsonl", "eval.jsonl"},
		},
		{
			name:      "no resources: no bindings",
			resources: nil,
			wantLen:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &SecretInfo{
				Valid:         true,
				GroqResources: tt.resources,
			}

			result := secretInfoToAnalyzerResult(info)
			if result == nil {
				t.Fatal("secretInfoToAnalyzerResult() returned nil")
			}

			if len(result.Bindings) != tt.wantLen {
				t.Errorf("got %d bindings, want %d", len(result.Bindings), tt.wantLen)
			}

			// Mirrors the four proto min_len constraints so this test fails for
			// the same reason the enterprise API does.
			for i, binding := range result.Bindings {
				if binding.Resource.Name == "" {
					t.Errorf("binding[%d].Resource.Name is empty", i)
				}
				if binding.Resource.Type == "" {
					t.Errorf("binding[%d].Resource.Type is empty", i)
				}
				if binding.Resource.FullyQualifiedName == "" {
					t.Errorf("binding[%d].Resource.FullyQualifiedName is empty", i)
				}
				if binding.Permission.Value == "" {
					t.Errorf("binding[%d].Permission.Value is empty", i)
				}
			}

			for i, name := range tt.wantNames {
				if i >= len(result.Bindings) {
					break
				}
				if result.Bindings[i].Resource.Name != name {
					t.Errorf("binding[%d].Resource.Name = %q, want %q", i, result.Bindings[i].Resource.Name, name)
				}
			}
		})
	}
}

func TestAnalyzer_Analyze(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	apiKey := testSecrets.MustGetField("GROQ")

	tests := []struct {
		name    string
		apiKey  string
		want    string
		wantErr bool
	}{
		{
			name:    "valid dockerhub credentials",
			apiKey:  apiKey,
			want:    `{"AnalyzerType":2,"Bindings":[],"UnboundedResources":null,"Metadata":{"Valid_Key":true}}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{Cfg: &config.Config{}}
			got, err := a.Analyze(ctx, map[string]string{"key": tt.apiKey})
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// marshal the actual result to JSON
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("could not marshal got to JSON: %s", err)
			}

			fmt.Println(string(gotJSON))

			// compare the JSON strings
			if string(gotJSON) != string(tt.want) {
				// pretty-print both JSON strings for easier comparison
				var gotIndented, wantIndented []byte
				gotIndented, err = json.MarshalIndent(got, "", " ")
				if err != nil {
					t.Fatalf("could not marshal got to indented JSON: %s", err)
				}
				wantIndented, err = json.MarshalIndent(tt.want, "", " ")
				if err != nil {
					t.Fatalf("could not marshal want to indented JSON: %s", err)
				}
				t.Errorf("Analyzer.Analyze() = %s, want %s", gotIndented, wantIndented)
			}
		})
	}
}
