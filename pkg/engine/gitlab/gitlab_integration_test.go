//go:build (!no_gitlab || !no_git) && integration

package gitlab

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestGitLab(t *testing.T) {
	// Run the scan.
	ctx := context.Background()
	e, err := engine.NewEngine(ctx, &engine.Config{
		Detectors:     defaults.DefaultDetectors(),
		SourceManager: sources.NewManager(),
		Verify:        false,
	})
	assert.NoError(t, err)
	e.Start(ctx)

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	_, err = Scan(ctx, sources.GitlabConfig{
		Token: secret.MustGetField("GITLAB_TOKEN"),
	}, e)
	assert.NoError(t, err)

	err = e.Finish(ctx)
	assert.NoError(t, err)

	// Check the output provided by metrics.
	metrics := e.GetMetrics()
	assert.GreaterOrEqual(t, metrics.ChunksScanned, uint64(36312))
	assert.GreaterOrEqual(t, metrics.BytesScanned, uint64(91618854))
}
