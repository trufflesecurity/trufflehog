package github

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestConnectorsImplementPersistentCloner(t *testing.T) {
	var _ persistentCloner = (*tokenConnector)(nil)
	var _ persistentCloner = (*appConnector)(nil)
	var _ persistentCloner = (*basicAuthConnector)(nil)
	var _ persistentCloner = (*unauthenticatedConnector)(nil)
}

func TestUnauthenticatedConnector_ClonePersistent(t *testing.T) {
	up := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-C", up}, args...)...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	run("init", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(up, "f"), []byte("a"), 0o644))
	run("add", "f")
	run("commit", "-m", "a")

	ctx := context.Background()
	clones := t.TempDir()
	c := &unauthenticatedConnector{}

	first, _, err := c.ClonePersistent(ctx, "file://"+up, clones)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(up, "f"), []byte("b"), 0o644))
	run("commit", "-am", "b")

	second, _, err := c.ClonePersistent(ctx, "file://"+up, clones)
	require.NoError(t, err)
	assert.Equal(t, first, second, "a later run reuses the same clone directory")
	assert.DirExists(t, first)
}
