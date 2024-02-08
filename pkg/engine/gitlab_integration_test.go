//go:build integration
// +build integration

package engine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestGitLab(t *testing.T) {
	// Run the scan.
	ctx := context.Background()
	e, err := Start(ctx,
		WithDetectors(DefaultDetectors()...),
		WithVerify(false),
	)
	assert.NoError(t, err)

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	err = e.ScanGitLab(ctx, sources.GitlabConfig{
		Token: secret.MustGetField("GITLAB_TOKEN"),
	})
	assert.NoError(t, err)

	err = e.Finish(ctx)
	assert.NoError(t, err)

	// Check the output provided by metrics.
	metrics := e.GetMetrics()
	assert.GreaterOrEqual(t, metrics.ChunksScanned, uint64(36312))
	assert.GreaterOrEqual(t, metrics.BytesScanned, uint64(91618854))
}
