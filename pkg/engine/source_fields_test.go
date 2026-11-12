package engine

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestScanGit_InitLogsHaveSourceFields(t *testing.T) {
	// make a small local repo with one commit to scan
	repoPath := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-q", "--allow-empty", "-m", "first"},
	} {
		out, err := exec.Command("git", append([]string{"-C", repoPath}, args...)...).CombinedOutput()
		require.NoError(t, err, string(out))
	}

	ctx, logs := logtest.DebugContext()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	e, err := NewEngine(ctx, &Config{
		Concurrency:   1,
		Decoders:      decoders.DefaultDecoders(),
		SourceManager: sources.NewManager(),
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	})
	require.NoError(t, err)
	e.Start(ctx)

	_, err = e.ScanGit(ctx, sources.GitConfig{URI: "file://" + repoPath})
	require.NoError(t, err)
	require.NoError(t, e.Finish(ctx))

	sourceFields := []string{"source_name", "source_type", "source_id", "job_id"}

	// the line the git source logs during Init has all the source fields
	initLines := logs.FilterMessage("git source initialized").All()
	require.Len(t, initLines, 1)
	for _, key := range sourceFields {
		assert.Contains(t, initLines[0].ContextMap(), key)
	}
	assert.Equal(t, "trufflehog - git", initLines[0].ContextMap()["source_name"])

	// the source manager adds the same fields for the scan,
	// so check no line ends up with any of them twice
	for _, entry := range logs.All() {
		for _, key := range sourceFields {
			count := 0
			for _, field := range entry.Context {
				if field.Key == key {
					count++
				}
			}
			assert.LessOrEqual(t, count, 1, "%s on %q", key, entry.Message)
		}
	}
}
