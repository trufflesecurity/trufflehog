package sources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJobReportFatalErrors(t *testing.T) {
	var jr JobReport

	// Add a non-fatal error.
	jr.AddError(fmt.Errorf("oh no"))
	assert.Error(t, jr.Errors())
	assert.NoError(t, jr.FatalError())
	assert.NoError(t, jr.ChunkErrors())

	// Add a fatal error and make sure we can test comparison.
	err := fmt.Errorf("fatal error")
	jr.AddError(Fatal{err})
	assert.Error(t, jr.Errors())
	assert.Error(t, jr.FatalError())
	assert.NoError(t, jr.ChunkErrors())
	assert.True(t, errors.Is(jr.FatalError(), err))

	// Add another fatal error and test we still return the first.
	jr.AddError(Fatal{fmt.Errorf("second fatal error")})
	assert.Error(t, jr.Errors())
	assert.Error(t, jr.FatalError())
	assert.NoError(t, jr.ChunkErrors())
	assert.True(t, errors.Is(jr.FatalError(), err))
}
