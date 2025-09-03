package cleantemp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitchellh/go-ps"
	"github.com/stretchr/testify/assert"
)

func TestExecName(t *testing.T) {
	executablePath, err := os.Executable()
	assert.Nil(t, err)
	execName := filepath.Base(executablePath)
	assert.Equal(t, "cleantemp.test", execName)

	procs, err := ps.Processes()
	assert.Nil(t, err)
	assert.NotEmpty(t, procs)

	found := false
	for _, proc := range procs {
		if proc.Executable() == execName {
			found = true
		}
	}

	assert.True(t, found)
}

func TestCleanTempDirsForLegacyJSON(t *testing.T) {
	baseDir := t.TempDir()

	// Create dirs that should be deleted
	dir1 := filepath.Join(baseDir, "trufflehog-123")
	dir2 := filepath.Join(baseDir, "trufflehog-456")
	assert.NoError(t, os.Mkdir(dir1, 0o755))
	assert.NoError(t, os.Mkdir(dir2, 0o755))

	// Create dirs that should NOT be deleted
	keepDir := filepath.Join(baseDir, "keepme-123")
	assert.NoError(t, os.Mkdir(keepDir, 0o755))

	// Create a file with trufflehog- prefix (should not be deleted because only dirs are deleted)
	keepFile := filepath.Join(baseDir, "trufflehog-file")
	assert.NoError(t, os.WriteFile(keepFile, []byte("data"), 0o644))

	err := CleanTempDirsForLegacyJSON(baseDir)
	assert.NoError(t, err)

	_, err = os.Stat(dir1)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(dir2)
	assert.True(t, os.IsNotExist(err))

	_, err = os.Stat(keepDir)
	assert.NoError(t, err)

	_, err = os.Stat(keepFile)
	assert.NoError(t, err)
}
