package finegrained

import (
	"testing"
	"time"

	gh "github.com/google/go-github/v66/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	analyzerCommon "github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestAnalyzer_Analyze(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	analyzerSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "analyzers1")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "finegrained - github-allrepos-actionsRW-contentsRW-issuesRW",
			key:     analyzerSecrets.MustGetField("GITHUB_FINEGRAINED_ALLREPOS_ACTIONS_RW_CONTENTS_RW_ISSUES_RW"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			key := tt.key
			client := gh.NewClient(analyzers.NewAnalyzeClient(cfg)).WithAuthToken(key)

			md, err := analyzerCommon.GetTokenMetadata(key, client)
			if err != nil {
				t.Fatalf("could not get token metadata: %s", err)
			}

			_, err = AnalyzeFineGrainedToken(client, md, cfg.Shallow)
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
