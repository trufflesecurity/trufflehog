//go:build integration
// +build integration

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// createFilesystemTree is a helper function to create a temporary directory
// that contains all of the provided files and contents on the operating
// system's filesystem. Sub-directories will be created as needed. On success,
// the root directory is returned and the caller is responsible for removing it
// from the filesystem.
func createFilesystemTree(files map[string]string) (string, error) {
	parentDir, err := os.MkdirTemp("", "trufflehog-integration-test")
	if err != nil {
		return "", err
	}

	for path, contents := range files {
		fullPath := filepath.Join(parentDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			_ = os.RemoveAll(parentDir)
			return "", err
		}
		if err := os.WriteFile(fullPath, []byte(contents), 0644); err != nil {
			_ = os.RemoveAll(parentDir)
			return "", err
		}
	}
	return parentDir, nil
}

func TestFilesystem(t *testing.T) {
	// Setup test directory.
	rootDir, err := createFilesystemTree(map[string]string{
		"/foo":             "bar",
		"/bar":             "baz",
		"/dir/a":           "a",
		"/dir/b":           "b",
		"/dir/c":           "c",
		"/.ignore/file":    "this should be ignored",
		"/.ignore/sub/dir": "this should also be ignored",
	})
	assert.NoError(t, err)
	defer os.RemoveAll(rootDir)

	configDir, err := createFilesystemTree(map[string]string{
		"/exclude": ".ignore",
		// TODO: Test include configuration.
	})
	assert.NoError(t, err)
	defer os.RemoveAll(configDir)

	// Run the scan.
	ctx := context.Background()
	e, err := Start(ctx,
		WithDetectors(DefaultDetectors()...),
		WithVerify(false),
	)
	assert.NoError(t, err)
	err = e.ScanFileSystem(ctx, sources.FilesystemConfig{
		Paths:            []string{rootDir},
		ExcludePathsFile: filepath.Join(configDir, "exclude"),
	})
	assert.NoError(t, err)

	err = e.Finish(ctx)
	assert.NoError(t, err)

	// Check the output provided by metrics.
	metrics := e.GetMetrics()
	assert.Equal(t, uint64(5), metrics.ChunksScanned)
	assert.Equal(t, uint64(9), metrics.BytesScanned)
}
