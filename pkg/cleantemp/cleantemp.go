package cleantemp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mitchellh/go-ps"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Returns a temporary directory path formatted as:
// trufflehog-<pid>-<randint>
func MkdirTemp() (string, error) {
	pid := os.Getpid()
	tmpdir := fmt.Sprintf("%s-%d-", "trufflehog", pid)
	dir, err := os.MkdirTemp(os.TempDir(), tmpdir)
	if err != nil {
		return "", err
	}
	return dir, nil
}

// Defines the interface for removing orphaned artifacts from aborted scans
type CleanTemp interface {
	//Removes orphaned directories from sources like Git
	CleanTempDir(ctx logContext.Context, dirName string, pid int) error
	//Removes orphaned files/artifacts from sources like Artifactory
	CleanTempFiles(ctx context.Context, fileName string, pid int) error
}

// Deletes orphaned temp directories that do not contain running PID values
func CleanTempDir(ctx logContext.Context, dirName string, pid int) error {
	// Finds other trufflehog PIDs that may be running
	var pids []string
	procs, err := ps.Processes()
	if err != nil {
		return fmt.Errorf("error getting jobs PIDs: %w", err)
	}

	for _, proc := range procs {
		if strings.Contains(proc.Executable(), dirName) {
			pids = append(pids, strconv.Itoa(proc.Pid()))
		}
	}

	tempDir := os.TempDir()
	files, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Errorf("Error reading temp dir: %w", err)
	}

	// Current PID
	pidStr := strconv.Itoa(pid)

	for _, file := range files {
		// Make sure we don't delete the working dir of the current PID
		if file.IsDir() && strings.Contains(file.Name(), dirName) && !strings.Contains(file.Name(), pidStr) {
			for _, pidval := range pids {
				// Make sure not to delete directories that may be tied to other instances of trufflehog
				if !strings.Contains(file.Name(), pidval) {
					dirPath := filepath.Join(tempDir, file.Name())
					if err := os.RemoveAll(dirPath); err != nil {
						return fmt.Errorf("Error deleting temp directory: %s", dirPath)
					}
					ctx.Logger().V(1).Info("Deleted directory", "directory", dirPath)

				}
			}
		}
	}
	return nil
}
