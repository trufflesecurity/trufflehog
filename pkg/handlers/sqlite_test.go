package handlers

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestHandleSqliteFile(t *testing.T) {
	file, err := os.Open("testdata/testdb.sqlite")
	assert.Nil(t, err)
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	r, err := newFileReader(ctx, file)
	assert.NoError(t, err)
	defer r.Close() //nolint:errcheck
	handler := newSqliteHandler()
	dataOrErrChan := handler.HandleFile(context.AddLogger(ctx), r)
	count := 0
	wantCount := 2
	for e := range dataOrErrChan {
		assert.NoError(t, e.Err)
		count++
	}
	assert.Equal(t, wantCount, count)
}
