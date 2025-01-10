package handlers

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestHandleNonArchiveFile(t *testing.T) {
	file, err := os.Open("testdata/nonarchive.txt")
	assert.Nil(t, err)
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	assert.NoError(t, err)
	defer rdr.Close()

	handler := newDefaultHandler(defaultHandlerType)
	dataOrErrChan := handler.HandleFile(context.AddLogger(ctx), rdr)
	assert.NoError(t, err)

	wantChunkCount := 6
	count := 0
	for range dataOrErrChan {
		count++
	}

	assert.Equal(t, wantChunkCount, count)
}
