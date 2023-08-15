package handlers

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestExtractDebContent(t *testing.T) {
	// Open the sample .deb file from the testdata folder.
	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)
	defer file.Close()

	ctx := context.Background()

	reader, err := extractDebContent(ctx, file)
	assert.Nil(t, err)

	content, err := io.ReadAll(reader)
	assert.Nil(t, err)
	expectedLength := 1015582
	assert.Equal(t, expectedLength, len(string(content)))
}
