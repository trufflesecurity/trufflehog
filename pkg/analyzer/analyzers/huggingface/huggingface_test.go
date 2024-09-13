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
