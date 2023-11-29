package cleantemp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecName(t *testing.T) {
	executablePath, err := os.Executable()
	assert.Nil(t, err)
	execName := filepath.Base(executablePath)
	assert.Equal(t, "cleantemp.test", execName)
}
