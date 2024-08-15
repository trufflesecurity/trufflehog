package slack

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
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
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
			name: "valid Slack key",
			key:  testSecrets.MustGetField("SLACK"),
			want: `{
					"AnalyzerType": 16,
					"Bindings": [
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "conversations.history",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "conversations.replies",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "channels.info",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "conversations.info",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "conversations.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "conversations.members",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "groups.info",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "im.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "mpim.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "users.conversations",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "emoji.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "files.info",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "files.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "stars.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "pins.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "usergroups.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "usergroups.users.list",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "dnd.info",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "dnd.teamInfo",
							"Parent": null
						}
						},
						{
						"Resource": {
							"Name": "marge.haskell.bridge",
							"FullyQualifiedName": "USMD5JM0F",
							"Type": "user",
							"Metadata": {
							"scopes": [
								"identify",
								"channels:history",
								"groups:history",
								"im:history",
								"channels:read",
								"emoji:read",
								"files:read",
								"groups:read",
								"im:read",
								"stars:read",
								"pins:read",
								"usergroups:read",
								"dnd:read",
								"calls:read"
							],
							"team": "ct.org",
							"team_id": "TSMCXP5FH",
							"url": "https://ctorgworkspace.slack.com/"
							},
							"Parent": null
						},
						"Permission": {
							"Value": "calls.info",
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
