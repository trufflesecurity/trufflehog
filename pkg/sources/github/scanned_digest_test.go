package github

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func TestCommitScannedDigests(t *testing.T) {
	dir := t.TempDir()
	out, err := exec.Command("git", "-C", dir, "init", "-b", "main").CombinedOutput()
	require.NoError(t, err, string(out))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f"), []byte("a"), 0o644))

	ctx := context.Background()
	s := &Source{}
	s.queueScannedDigest(dir, "abc123")
	assert.Empty(t, git.ScannedRefsDigest(ctx, dir), "queued digests are not recorded before the engine finishes")

	s.CommitScannedDigests(ctx)
	assert.Equal(t, "abc123", git.ScannedRefsDigest(ctx, dir))

	// Committing twice must not re-record anything.
	require.NoError(t, git.SetScannedRefsDigest(ctx, dir, "changed"))
	s.CommitScannedDigests(ctx)
	assert.Equal(t, "changed", git.ScannedRefsDigest(ctx, dir))
}

type stubReporter struct{ sources.ChunkReporter }

func (stubReporter) ChunkErr(context.Context, error) error { return nil }

func TestErrTrackingReporter(t *testing.T) {
	r := &errTrackingReporter{ChunkReporter: stubReporter{}}
	assert.False(t, r.failed.Load())
	require.NoError(t, r.ChunkErr(context.Background(), assert.AnError))
	assert.True(t, r.failed.Load())
}
