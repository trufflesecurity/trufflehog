package cleantemp

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

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

	if len(pids) == 0 {
		ctx.Logger().V(5).Info("No trufflehog processes were found")
		return nil
	}

	tempDir := os.TempDir()
	dir, err := os.Open(tempDir)
	if err != nil {
		return fmt.Errorf("error opening temp dir: %w", err)
	}
	defer dir.Close()

	for {
		entries, err := dir.ReadDir(1) // read only one entry
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		entry := entries[0]

		if trufflehogRE.MatchString(entry.Name()) {

			// Mark these artifacts initially as ones that should be deleted.
			shouldDelete := true
			// Check if the name matches any live PIDs.
			// Potential race condition here if a PID is started and creates tmp data after the initial check.
			for _, pidval := range pids {
				if strings.Contains(entry.Name(), fmt.Sprintf("-%s-", pidval)) {
					shouldDelete = false
					break
				}
			}

			if shouldDelete {
				path := filepath.Join(tempDir, entry.Name())
				isDir := entry.IsDir()
				if isDir {
					err = os.RemoveAll(path)
				} else {
					err = os.Remove(path)
				}
				if err != nil {
					return fmt.Errorf("error deleting temp artifact (dir: %v) %s: %w", isDir, path, err)
				}

				ctx.Logger().V(4).Info("Deleted orphaned temp artifact", "artifact", path)
			}
		}
	}

	return nil
}
