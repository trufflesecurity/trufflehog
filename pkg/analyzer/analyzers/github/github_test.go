package github

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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

	analyzerSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "analyzers1")
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
			name:    "finegrained - github-allrepos-actionsRW-contentsRW-issuesRW",
			key:     analyzerSecrets.MustGetField("GITHUB_FINEGRAINED_ALLREPOS_ACTIONS_RW_CONTENTS_RW_ISSUES_RW"),
			wantErr: false,
			want: `{
              "AnalyzerType": 7,
              "Bindings": [
                {
                  "Resource": {
                    "Name": "private",
                    "FullyQualifiedName": "github.com/sirdetectsalot/private",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "actions:write",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "private",
                    "FullyQualifiedName": "github.com/sirdetectsalot/private",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "contents:write",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "private",
                    "FullyQualifiedName": "github.com/sirdetectsalot/private",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "deployments:read",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "private",
                    "FullyQualifiedName": "github.com/sirdetectsalot/private",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "issues:write",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "private",
                    "FullyQualifiedName": "github.com/sirdetectsalot/private",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "metadata:read",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "public",
                    "FullyQualifiedName": "github.com/sirdetectsalot/public",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "actions:write",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "public",
                    "FullyQualifiedName": "github.com/sirdetectsalot/public",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "contents:write",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "public",
                    "FullyQualifiedName": "github.com/sirdetectsalot/public",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "deployments:read",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "public",
                    "FullyQualifiedName": "github.com/sirdetectsalot/public",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "issues:write",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "public",
                    "FullyQualifiedName": "github.com/sirdetectsalot/public",
                    "Type": "repository",
                    "Metadata": null,
                    "Parent": {
                      "Name": "sirdetectsalot",
                      "FullyQualifiedName": "github.com/sirdetectsalot",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "metadata:read",
                    "Parent": null
                  }
                }
              ],
              "UnboundedResources": null,
              "Metadata": {
                "owner": "sirdetectsalot",
                "expiration": "2025-08-05T00:00:00-07:00",
                "type": "Fine-Grained GitHub Personal Access Token"
              }
            }`,
		},
		{
			name: "v2 ghp",
			key:  testSecrets.MustGetField("GITHUB_VERIFIED_GHP"),
			want: `{
              "AnalyzerType": 7,
              "Bindings": [
                {
                  "Resource": {
                    "Name": "truffle-sandbox",
                    "FullyQualifiedName": "github.com/truffle-sandbox",
                    "Type": "user",
                    "Metadata": null,
                    "Parent": null
                  },
                  "Permission": {
                    "Value": "notifications",
                    "AccessLevel": "",
                    "Parent": null
                  }
                },
                {
                  "Resource": {
                    "Name": "public gist",
                    "FullyQualifiedName": "gist.github.com/truffle-sandbox/fecf272c606ddbc5f8486f9c44821312",
                    "Type": "gist",
                    "Metadata": null,
                    "Parent": {
                      "Name": "truffle-sandbox",
                      "FullyQualifiedName": "github.com/truffle-sandbox",
                      "Type": "user",
                      "Metadata": null,
                      "Parent": null
                    }
                  },
                  "Permission": {
                    "Value": "notifications",
                    "Parent": null
                  }
                }
              ],
              "UnboundedResources": null,
              "Metadata": {
                "owner": "truffle-sandbox",
                "expiration": "0001-01-01T00:00:00Z",
                "type": "Classic GitHub Personal Access Token"
              }
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
			gotJSON, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatalf("could not marshal got to JSON: %s", err)
			}

			// Parse the expected JSON string
			var wantObj analyzers.AnalyzerResult
			if err := json.Unmarshal([]byte(tt.want), &wantObj); err != nil {
				t.Fatalf("could not unmarshal want JSON string: %s", err)
			}

			// Marshal the expected result to JSON with indentation
			wantJSON, err := json.MarshalIndent(wantObj, "", "  ")
			if err != nil {
				t.Fatalf("could not marshal want to JSON: %s", err)
			}

			// Compare the JSON strings and show diff if they don't match
			if string(gotJSON) != string(wantJSON) {
				diff := cmp.Diff(string(wantJSON), string(gotJSON))
				t.Errorf("Analyzer.Analyze() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
