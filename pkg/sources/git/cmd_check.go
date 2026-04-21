package git

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
)

// Extract the version string using a regex to find the version numbers
var regex = regexp.MustCompile(`\d+\.\d+\.\d+`)

// CmdCheck checks if git is installed and meets 2.20.0<=x<3.0.0 version requirements.
func CmdCheck() error {
	if errors.Is(exec.Command("git").Run(), exec.ErrNotFound) {
		return fmt.Errorf("'git' command not found in $PATH. Make sure git is installed and included in $PATH")
	}

	// Check the version is greater than or equal to 2.20.0
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		return fmt.Errorf("failed to check git version: %w", err)
	}

	versionStr := regex.FindString(string(out))
	versionParts := strings.Split(versionStr, ".")

	// Parse version numbers
	major, _ := strconv.Atoi(versionParts[0])
	minor, _ := strconv.Atoi(versionParts[1])

	// Compare with version 2.20.0<=x<3.0.0
	if major == 2 && minor >= 20 {
		return nil
	}
	return fmt.Errorf("git version is %s, but must be greater than or equal to 2.20.0, and less than 3.0.0", versionStr)
}
