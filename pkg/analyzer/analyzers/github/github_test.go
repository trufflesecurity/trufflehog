package github

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	gh "github.com/google/go-github/v67/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	githubcommon "github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func strPtr(s string) *string { return &s }

func makeOwner(login, userType string) *gh.User {
	return &gh.User{Login: &login, Type: &userType}
}

// TestSecretInfoToGistBindings exercises nil-field edge cases that caused a
// production panic (nil Description and nil Owner from the GitHub API).
func TestSecretInfoToGistBindings(t *testing.T) {
	owner := makeOwner("truffle-sandbox", "User")
	scope := []analyzers.Permission{{Value: "gist"}}

	tests := []struct {
		name      string
		gists     []*gh.Gist
		wantLen   int
		wantFQNs  []string
		wantNames []string // parallel to wantFQNs; checked unconditionally (including empty string)
	}{
		{
			name: "nil description produces empty name, gist is still included",
			gists: []*gh.Gist{
				{ID: strPtr("abc123"), Description: nil, Owner: owner},
			},
			wantLen:   1,
			wantFQNs:  []string{"gist.github.com/truffle-sandbox/abc123"},
			wantNames: []string{""},
		},
		{
			name: "nil owner: gist is skipped entirely",
			gists: []*gh.Gist{
				{ID: strPtr("abc123"), Description: strPtr("my gist"), Owner: nil},
			},
			wantLen: 0,
		},
		{
			name: "mix of valid and nil-owner gists: only valid gist is included",
			gists: []*gh.Gist{
				{ID: strPtr("abc123"), Description: strPtr("valid gist"), Owner: owner},
				{ID: strPtr("def456"), Description: strPtr("no owner"), Owner: nil},
			},
			wantLen:   1,
			wantFQNs:  []string{"gist.github.com/truffle-sandbox/abc123"},
			wantNames: []string{"valid gist"},
		},
		{
			name:    "empty gist list: no bindings",
			gists:   nil,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &githubcommon.SecretInfo{
				Metadata: &githubcommon.TokenMetadata{OauthScopes: scope},
				Gists:    tt.gists,
			}
			got := secretInfoToGistBindings(info)
			if len(got) != tt.wantLen {
				t.Errorf("got %d bindings, want %d", len(got), tt.wantLen)
			}
			for i, fqn := range tt.wantFQNs {
				if i >= len(got) {
					break
				}
				if got[i].Resource.FullyQualifiedName != fqn {
					t.Errorf("binding[%d].FullyQualifiedName = %q, want %q", i, got[i].Resource.FullyQualifiedName, fqn)
				}
			}
			for i, name := range tt.wantNames {
				if i >= len(got) {
					break
				}
				if got[i].Resource.Name != name {
					t.Errorf("binding[%d].Name = %q, want %q", i, got[i].Resource.Name, name)
				}
			}
		})
	}
}

// TestSecretInfoToRepoBindings verifies that a repo with a nil Owner is still
// emitted (with Parent left unset) rather than skipped, since a repo has
// identity independent of its owner.
func TestSecretInfoToRepoBindings(t *testing.T) {
	owner := makeOwner("truffle-sandbox", "User")
	scope := []analyzers.Permission{{Value: "repo"}}

	tests := []struct {
		name          string
		repos         []*gh.Repository
		wantLen       int
		wantFQNs      []string
		wantParentNil []bool // parallel to wantFQNs
	}{
		{
			name: "valid repo produces binding with populated parent",
			repos: []*gh.Repository{
				{Name: strPtr("my-repo"), FullName: strPtr("truffle-sandbox/my-repo"), Owner: owner},
			},
			wantLen:       1,
			wantFQNs:      []string{"github.com/truffle-sandbox/my-repo"},
			wantParentNil: []bool{false},
		},
		{
			name: "nil owner: repo is still included with nil parent",
			repos: []*gh.Repository{
				{Name: strPtr("my-repo"), FullName: strPtr("truffle-sandbox/my-repo"), Owner: nil},
			},
			wantLen:       1,
			wantFQNs:      []string{"github.com/truffle-sandbox/my-repo"},
			wantParentNil: []bool{true},
		},
		{
			name: "mix of valid and nil-owner repos: both included, parent populated only for valid",
			repos: []*gh.Repository{
				{Name: strPtr("my-repo"), FullName: strPtr("truffle-sandbox/my-repo"), Owner: owner},
				{Name: strPtr("other"), FullName: strPtr("truffle-sandbox/other"), Owner: nil},
			},
			wantLen:       2,
			wantFQNs:      []string{"github.com/truffle-sandbox/my-repo", "github.com/truffle-sandbox/other"},
			wantParentNil: []bool{false, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &githubcommon.SecretInfo{
				Metadata: &githubcommon.TokenMetadata{
					Type:        githubcommon.TokenTypeClassicPAT,
					OauthScopes: scope,
				},
				Repos: tt.repos,
			}
			got := secretInfoToRepoBindings(info)
			if len(got) != tt.wantLen {
				t.Errorf("got %d bindings, want %d", len(got), tt.wantLen)
			}
			for i, fqn := range tt.wantFQNs {
				if i >= len(got) {
					break
				}
				if got[i].Resource.FullyQualifiedName != fqn {
					t.Errorf("binding[%d].FullyQualifiedName = %q, want %q", i, got[i].Resource.FullyQualifiedName, fqn)
				}
			}
			for i, wantNil := range tt.wantParentNil {
				if i >= len(got) {
					break
				}
				gotNil := got[i].Resource.Parent == nil
				if gotNil != wantNil {
					t.Errorf("binding[%d].Parent nil = %v, want %v", i, gotNil, wantNil)
				}
			}
		})
	}
}

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
                "expiration": "2026-03-24T15:27:38+05:00",
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
