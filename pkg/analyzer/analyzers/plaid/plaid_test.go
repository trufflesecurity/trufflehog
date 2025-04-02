package plaid

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

//go:embed expected_output.json
var expectedOutput []byte

func TestAnalyzer_Analyze(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	secret := testSecrets.MustGetField("PLAIDKEY_SECRET")
	clientID := testSecrets.MustGetField("PLAIDKEY_CLIENTID")
	accessToken := testSecrets.MustGetField("PLAIDKEY_ACCESS_TOKEN")

	tests := []struct {
		name        string
		clientID    string
		secret      string
		accessToken string
		want        string
		wantErr     bool
	}{
		{
			name:        "valid plaid credentials",
			clientID:    clientID,
			secret:      secret,
			accessToken: accessToken,
			want:        string(expectedOutput),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{Cfg: &config.Config{}}
			got, err := a.Analyze(ctx, map[string]string{
				"secret": tt.secret,
				"id":     tt.clientID,
				"token":  tt.accessToken,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// marshal the actual result to JSON
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("could not marshal got to JSON: %s", err)
			}

			fmt.Println(string(gotJSON))

			// compare the JSON strings
			if string(gotJSON) != string(tt.want) {
				// pretty-print both JSON strings for easier comparison
				var gotIndented, wantIndented []byte
				gotIndented, err = json.MarshalIndent(got, "", " ")
				if err != nil {
					t.Fatalf("could not marshal got to indented JSON: %s", err)
				}
				wantIndented, err = json.MarshalIndent(tt.want, "", " ")
				if err != nil {
					t.Fatalf("could not marshal want to indented JSON: %s", err)
				}
				t.Errorf("Analyzer.Analyze() = %s, want %s", gotIndented, wantIndented)
			}
		})
	}
}
