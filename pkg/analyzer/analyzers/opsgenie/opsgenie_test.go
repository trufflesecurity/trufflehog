package opsgenie

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
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	key := testSecrets.MustGetField("OPSGENIE")

	tests := []struct {
		name    string
		key     string
		want    string // JSON string
		wantErr bool
	}{
		{
			name: "valid Opsgenie API key",
			key:  key,
			want: `{
					"AnalyzerType": 11,
					"Bindings": [
						{
						"Resource": {
							"Name": "Opsgenie API Integration Key",
							"FullyQualifiedName": "Opsgenie API Integration Key",
							"Type": "API Key",
							"Metadata": {
							"expires": "never"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "configuration_access",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "Opsgenie API Integration Key",
							"FullyQualifiedName": "Opsgenie API Integration Key",
							"Type": "API Key",
							"Metadata": {
							"expires": "never"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "read",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "Opsgenie API Integration Key",
							"FullyQualifiedName": "Opsgenie API Integration Key",
							"Type": "API Key",
							"Metadata": {
							"expires": "never"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "delete",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "Opsgenie API Integration Key",
							"FullyQualifiedName": "Opsgenie API Integration Key",
							"Type": "API Key",
							"Metadata": {
							"expires": "never"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "create_and_update",
							"Parent": null
						}
						}
					],
					"UnboundedResources": [
						{
						"Name": "John Scanner",
						"FullyQualifiedName": "secretscanner02@zohomail.com",
						"Type": "user",
						"Metadata": {
							"role": "Owner",
							"username": "secretscanner02@zohomail.com"
						},
						"Parent": null
						}
					],
					"Metadata": null
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
