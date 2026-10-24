package handlers

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCappedPPMdReaderRejectsLargeModelMemory(t *testing.T) {
	props := []byte{6, 0, 0, 0, 0}
	readers := func() []io.ReadCloser { return []io.ReadCloser{io.NopCloser(bytes.NewReader(make([]byte, 16)))} }

	binary.LittleEndian.PutUint32(props[1:], 0xF0000000)
	_, err := newCappedPPMdReader(props, 10, readers())
	assert.ErrorContains(t, err, "exceeds limit")

	binary.LittleEndian.PutUint32(props[1:], 1<<20)
	rc, err := newCappedPPMdReader(props, 10, readers())
	assert.NoError(t, err)
	assert.NoError(t, rc.Close())
}
