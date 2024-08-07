package mailgun

import (
	"encoding/json"
	"sort"
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
			name: "valid Mailgun key",
			key:  testSecrets.MustGetField("MAILGUN_TOKEN"),
			want: `{
				"AnalyzerType":8,
				"Bindings":[
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"mailing_lists:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"templates:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"events:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"complaints:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"whitelist:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"sub_accounts:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"secure_tracking:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"webhooks:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"tags:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"ips:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"ip_pools:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"sub_accounts:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"domains:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"webhooks:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"unsubscribes:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"complaints:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"mailing_lists:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"domains:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"ips:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"templates:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"ip_pools:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"messages:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"events:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"stats:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"bounces:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"whitelist:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"tags:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"stats:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"bounces:read",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"routes:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"secure_tracking:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"messages:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"unsubscribes:write",
						 "Parent":null
					  }
				   },
				   {
					  "Resource":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  },
					  "Permission":{
						 "Value":"routes:read",
						 "Parent":null
					  }
				   }
				],
				"UnboundedResources":[
				   {
					  "Name":"sandbox19e49763d44e498e850589ea7d54bd82.mailgun.org",
					  "FullyQualifiedName":"sandbox19e49763d44e498e850589ea7d54bd82.mailgun.org",
					  "Type":"domain",
					  "Metadata":{
						 "created_at":"Thu, 01 Jun 2023 16:45:37 GMT",
						 "is_disabled":false,
						 "state":"active",
						 "type":"sandbox"
					  },
					  "Parent":{
						 "Name":"Mailgun API Key",
						 "FullyQualifiedName":"Mailgun API Key",
						 "Type":"api key",
						 "Metadata":{
							"domains_count":1
						 },
						 "Parent":null
					  }
				   }
				],
				"Metadata":null
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

			// bindings need to be in the same order to be comparable
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

			// bindings need to be in the same order to be comparable
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
