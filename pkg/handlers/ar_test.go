package handlers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestHandleARFile(t *testing.T) {
	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	newReader, err := diskbufferreader.New(file)
	assert.NoError(t, err)
	defer newReader.Close()

	handler := &ARHandler{new(DefaultHandler)}
	archiveChan, err := handler.HandleFile(logContext.AddLogger(ctx), newReader)
	assert.NoError(t, err)

	wantChunkCount := 102
	count := 0
	for range archiveChan {
		count++
	}

	assert.Equal(t, wantChunkCount, count)
}
