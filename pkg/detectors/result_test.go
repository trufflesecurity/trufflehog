package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClearPrimarySecret(t *testing.T) {
	result := Result{}
	result.SetPrimarySecretValue("secret-value")
	result.SetPrimarySecretLine(12)

	result.ClearPrimarySecret()

	assert.Empty(t, result.GetPrimarySecretValue())
	assert.Zero(t, result.primarySecret.Line)
}
