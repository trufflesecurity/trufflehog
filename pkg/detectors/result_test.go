package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClearSecrets(t *testing.T) {
	result := Result{
		Raw:         []byte("raw-secret"),
		RawV2:       []byte("raw-secret-v2"),
		Redacted:    "redacted",
		SecretParts: map[string]string{"key": "raw-secret"},
		ExtraData:   map[string]string{"account": "123"},
	}
	result.SetPrimarySecretValue("secret-value")
	result.SetPrimarySecretLine(12)
	result.SetVerificationError(assert.AnError)

	result.ClearSecrets()

	assert.Nil(t, result.Raw)
	assert.Nil(t, result.RawV2)
	assert.Nil(t, result.SecretParts)
	assert.Empty(t, result.GetPrimarySecretValue())
	assert.Zero(t, result.primarySecret.Line)
	assert.Equal(t, "redacted", result.Redacted)
	assert.Equal(t, map[string]string{"account": "123"}, result.ExtraData)
	assert.EqualError(t, result.VerificationError(), assert.AnError.Error())
}
