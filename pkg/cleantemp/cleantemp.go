package cleantemp

import (
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

const (
	defaultExecPath             = "trufflehog"
	defaultArtifactPrefixFormat = "%s-%d-"
)

// MkdirTemp returns a temporary directory path formatted as:
// trufflehog-<pid>-<randint>
func MkdirTemp() (string, error) {
	pid := os.Getpid()
	tmpdir := fmt.Sprintf(defaultArtifactPrefixFormat, defaultExecPath, pid)
	dir, err := os.MkdirTemp(os.TempDir(), tmpdir)
	if err != nil {
		return "", err
	}
	return dir, nil
}

// Unlike MkdirTemp, we only want to generate the filename string.
// The tempfile creation in trufflehog we're interested in
// is generally handled by "github.com/trufflesecurity/disk-buffer-reader"
func MkFilename() string {
	pid := os.Getpid()
	filename := fmt.Sprintf(defaultArtifactPrefixFormat, defaultExecPath, pid)
	return filename
}

// Only compile during startup.
var trufflehogRE = regexp.MustCompile(`^trufflehog-\d+-\d+$`)

// CleanTempArtifacts deletes orphaned temp directories and files that do not contain running PID values.
func CleanTempArtifacts(ctx logContext.Context) error {
	executablePath, err := os.Executable()
	if err != nil {
		executablePath = defaultExecPath
	}
	execName := filepath.Base(executablePath)

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
	artifacts, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Errorf("error reading temp dir: %w", err)
	}

	for _, artifact := range artifacts {
		if trufflehogRE.MatchString(artifact.Name()) {
			// Mark these artifacts initially as ones that should be deleted.
			shouldDelete := true
			// Check if the name matches any live PIDs.
			for _, pidval := range pids {
				if strings.Contains(artifact.Name(), fmt.Sprintf("-%s-", pidval)) {
					shouldDelete = false
					break
				}
			}

			if shouldDelete {
				artifactPath := filepath.Join(tempDir, artifact.Name())

				var err error
				if artifact.IsDir() {
					err = os.RemoveAll(artifactPath)
				} else {
					err = os.Remove(artifactPath)
				}
				if err != nil {
					return fmt.Errorf("Error deleting temp artifact: %s", artifactPath)
				}

				ctx.Logger().Info("Deleted orphaned temp artifact", "artifact", artifactPath)
			}
		}
	}

	return nil
}

// RunCleanupLoop runs a loop that cleans up orphaned directories every 15 seconds.
func RunCleanupLoop(ctx logContext.Context) {
	err := CleanTempArtifacts(ctx)
	if err != nil {
		ctx.Logger().Error(err, "Error cleaning up orphaned directories ")
	}

	const cleanupLoopInterval = 15 * time.Second
	ticker := time.NewTicker(cleanupLoopInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := CleanTempArtifacts(ctx); err != nil {
				ctx.Logger().Error(err, "error cleaning up orphaned directories")
			}
		case <-ctx.Done():
			ctx.Logger().Info("Cleanup loop exiting due to context cancellation")
			return
		}
	}
}
