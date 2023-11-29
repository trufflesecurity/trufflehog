package cleantemp

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/mitchellh/go-ps"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func GetPids(artifactName string) ([]string, error) {
	// Finds other trufflehog PIDs that may be running
	var pids []string
	procs, err := ps.Processes()
	if err != nil {
		return pids, fmt.Errorf("error getting jobs PIDs: %w", err)
	}

	for _, proc := range procs {
		if strings.Contains(proc.Executable(), artifactName) {
			pids = append(pids, strconv.Itoa(proc.Pid()))
		}
	}
	return pids, err
}

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

// Unlike MkdirTemp, we only want to generate the filename string.
// The tempfile creation in trufflehog we're interested in
// is generally handled by "github.com/trufflesecurity/disk-buffer-reader"
func MkFilename() string {
	pid := os.Getpid()
	filename := fmt.Sprintf("%s-%d-", "trufflehog", pid)
	return filename
}

// CleanTempArtifacts deletes orphaned temp directories and files that do not contain running PID values
func CleanTempArtifacts(ctx logContext.Context, artifactName string, pid int) error {
	pids, err := GetPids(artifactName)
	if err != nil {
		return err
	}

	tempDir := os.TempDir()
	files, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Errorf("error reading temp dir: %w", err)
	}

	// Current PID
	pidStr := strconv.Itoa(pid)

	pattern := `^trufflehog-\d+-\d+$`
	re := regexp.MustCompile(pattern)

	for _, file := range files {
		// Match files or directories excluding the current PID
		if re.MatchString(file.Name()) && !strings.Contains(file.Name(), pidStr) {
			shouldDelete := true
			// Check if the name matches any live PIDs
			for _, pidval := range pids {
				if strings.Contains(file.Name(), pidval) {
					shouldDelete = false
					break
				}
			}

			if shouldDelete {
				artifactPath := filepath.Join(tempDir, file.Name())

				var delErr error
				if file.IsDir() {
					delErr = os.RemoveAll(artifactPath)
				} else {
					delErr = os.Remove(artifactPath)
				}

				if delErr != nil {
					return fmt.Errorf("error deleting temp artifact: %s", artifactPath)
				}
				ctx.Logger().V(1).Info("Deleted artifact", "artifact", artifactPath)
			}
		}
	}
	return nil
}
