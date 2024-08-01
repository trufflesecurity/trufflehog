package twilio

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
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

	tests := []struct {
		name    string
		key     string
		want    string // JSON string
		wantErr bool
	}{
		{
			name: "valid Twilio key",
			key:  testSecrets.MustGetField("TWILLIO_ID") + ":" + testSecrets.MustGetField("TWILLIO_API"),
			want: `            {
             "AnalyzerType": 20,
             "Bindings": [
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "account_management:read",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "account_management:write",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "subaccount_configuration:read",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "subaccount_configuration:write",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "key_management:read",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "key_management:write",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "service_verification:read",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "service_verification:write",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "sms:read",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "sms:write",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "voice:read",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "voice:write",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "messaging:read",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "messaging:write",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "call_management:read",
                "Parent": null
               }
              },
              {
               "Resource": {
                "Name": "My first Twilio account",
                "FullyQualifiedName": "twilio.com/account/ACa5b6165773490f33f226d71e7ffacff5",
                "Type": "Account",
                "Metadata": null,
                "Parent": null
               },
               "Permission": {
                "Value": "call_management:write",
                "Parent": null
               }
              }
             ],
             "UnboundedResources": null,
             "Metadata": null
            }`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{}
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
				var gotIndented []byte
				gotIndented, err = json.MarshalIndent(got, "", " ")
				if err != nil {
					t.Fatalf("could not marshal got to indented JSON: %s", err)
				}
				t.Errorf("Analyzer.Analyze() = \n%s", gotIndented)
			}
		})
	}
}
