package dockerhub

import (
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

//go:embed result_output.json
var expectedOutput []byte

func repo(name string) Repository {
	return Repository{
		ID:        "user123/repo/image/" + name,
		Name:      name,
		Type:      "image",
		IsPrivate: true,
		StarCount: 1,
		PullCount: 2,
	}
}

func TestSecretInfoToAnalyzerResult(t *testing.T) {
	tests := []struct {
		name      string
		repos     []Repository
		wantLen   int
		wantNames []string
	}{
		{
			name:      "one repository produces exactly one binding",
			repos:     []Repository{repo("repo1")},
			wantLen:   1,
			wantNames: []string{"repo1"},
		},
		{
			name:      "three repositories produce exactly three bindings, not six",
			repos:     []Repository{repo("repo1"), repo("repo2"), repo("repo3")},
			wantLen:   3,
			wantNames: []string{"repo1", "repo2", "repo3"},
		},
		{
			name:    "no repositories: no bindings",
			repos:   nil,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &SecretInfo{
				Valid:        true,
				User:         User{ID: "uuid-123", Username: "user123", Email: "user123@example.com"},
				Permissions:  []string{"repo:admin"},
				Repositories: tt.repos,
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
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	username := testSecrets.MustGetField("DOCKERHUB_USERNAME")
	pat := testSecrets.MustGetField("DOCKERHUB_PAT")

	tests := []struct {
		name     string
		username string
		pat      string
		want     []byte // JSON string
		wantErr  bool
	}{
		{
			name:     "valid dockerhub credentials",
			username: username,
			pat:      pat,
			want:     expectedOutput,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{Cfg: &config.Config{}}
			got, err := a.Analyze(ctx, map[string]string{"username": tt.username, "pat": tt.pat})
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
