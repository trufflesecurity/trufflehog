package asana

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
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors3")
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
			name: "valid Asana OAUTH Token",
			key:  testSecrets.MustGetField("ASANAOAUTH_TOKEN"),
			want: `{"AnalyzerType":0,"Bindings":[{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"projects:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"sections:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"tags:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"events:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"users:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"memberships:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"project_memberships:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"projects:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"project_memberships:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"tasks:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"memberships:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"custom_field_settings:write","Parent":null}},
			{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"custom_fields:write","Parent":null}},
			{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"jobs:write","Parent":null}},
			{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"user_task_lists:write","Parent":null}},
			{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"custom_fields:read","Parent":null}},
			{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"attachments:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"batch_api:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"portfolios:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"teams:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"rules:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"rules:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"allocations:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},
			"Parent":null},"Permission":{"Value":"goals:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"jobs:read","Parent":null}},
			{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"tags:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"tasks:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},
			"Permission":{"Value":"autdit_logs:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"batch_api:write","Parent":null}},{"Resource":{"Name":"John Done",
			"FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"events:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"portfolios:write","Parent":null}},
			{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"sections:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"teams:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"user_task_lists:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"allocations:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"autdit_logs:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"custom_field_settings:read","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"goals:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user",
			"Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"users:write","Parent":null}},{"Resource":{"Name":"John Done","FullyQualifiedName":"1200089577600156","Type":"user","Metadata":{"email":"away45846@gmail.com","type":"user"},"Parent":null},"Permission":{"Value":"attachments:read","Parent":null}}],
			"UnboundedResources":[{"Name":"Engineering","FullyQualifiedName":"1200089577216305","Type":"workspace","Metadata":null,"Parent":null}],"Metadata":null}`,
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
