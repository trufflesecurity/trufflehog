package cleantemp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/go-ps"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// MkdirTemp returns a temporary directory path formatted as:
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

// CleanTemp is used to remove orphaned artifacts from aborted scans.
type CleanTemp interface {
	// CleanTempDir removes orphaned directories from sources. ex: Git
	CleanTempDir(ctx logContext.Context, dirName string, pid int) error
	// CleanTempFiles removes orphaned files/artifacts from sources. ex: Artifactory
	CleanTempFiles(ctx context.Context, fileName string, pid int) error
}

// Only compile during startup.
var trufflehogRE = regexp.MustCompile(`^trufflehog-\d+-\d+$`)

// CleanTempDir removes orphaned temp directories that do not contain running PID values.
func CleanTempDir(ctx logContext.Context) error {
	const defaultExecPath = "trufflehog"
	executablePath, err := os.Executable()
	if err != nil {
		executablePath = defaultExecPath
	}
	execName := filepath.Base(executablePath)

	// Finds other trufflehog PIDs that may be running
	var pids []string
	procs, err := ps.Processes()
	if err != nil {
		return fmt.Errorf("error getting jobs PIDs: %w", err)
	}

	for _, proc := range procs {
		if proc.Executable() == execName {
			pids = append(pids, strconv.Itoa(proc.Pid()))
		}
	}

	tempDir := os.TempDir()
	dirs, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Errorf("error reading temp dir: %w", err)
	}

	for _, dir := range dirs {
		// Ensure that all directories match the pattern.
		if trufflehogRE.MatchString(dir.Name()) {
			// Mark these directories initially as ones that should be deleted.
			shouldDelete := true
			// If they match any live PIDs, mark as should not delete.
			for _, pidval := range pids {
				if strings.Contains(dir.Name(), fmt.Sprintf("-%s-", pidval)) {
					shouldDelete = false
					// break out so we can still delete directories even if no other Trufflehog processes are running.
					break
				}
			}
			if shouldDelete {
				dirPath := filepath.Join(tempDir, dir.Name())
				if err := os.RemoveAll(dirPath); err != nil {
					return fmt.Errorf("error deleting temp directory: %s", dirPath)
				}
				ctx.Logger().V(1).Info("Deleted directory", "directory", dirPath)
			}
		}
	}
	return nil
}

// RunCleanupLoop runs a loop that cleans up orphaned directories every 15 seconds
func RunCleanupLoop(ctx logContext.Context) {
	if err := CleanTempDir(ctx); err != nil {
		ctx.Logger().Error(err, "error cleaning up orphaned directories ")
	}

	const cleanupLoopInterval = 15 * time.Second
	ticker := time.NewTicker(cleanupLoopInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := CleanTempDir(ctx); err != nil {
				ctx.Logger().Error(err, "error cleaning up orphaned directories")
			}
		case <-ctx.Done():
			ctx.Logger().Info("Cleanup loop exiting due to context cancellation")
			return
		}
	}
}
