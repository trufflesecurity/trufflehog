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
