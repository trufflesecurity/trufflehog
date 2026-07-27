package groq

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

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
		wantErr bool
	}{
		{
			name:    "valid groq credentials",
			apiKey:  apiKey,
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

			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("could not marshal got to JSON: %s", err)
			}

			fmt.Println(string(gotJSON))

			if got == nil {
				t.Fatal("Analyzer.Analyze() returned nil result")
			}

			if got.Metadata["Valid_Key"] != true {
				t.Fatalf("expected Valid_Key metadata to be true, got %#v", got.Metadata["Valid_Key"])
			}

			if len(got.Bindings) == 0 {
				t.Fatal("expected at least one model binding for a valid Groq API key")
			}

			for _, binding := range got.Bindings {
				if binding.Permission.Value != PermissionStrings[FullAccess] {
					t.Fatalf("expected full_access permission, got %q", binding.Permission.Value)
				}
			}
		})
	}
}
