package handlers

import (
	"bytes"
	"archive/zip"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// corruptedZIPWithIntactSecondMember creates a ZIP archive in memory where the
// first member has its data bytes corrupted (causing a checksum error on read)
// and the second member contains an intact pattern.
func corruptedZIPWithIntactSecondMember(t *testing.T, corruptContent, intactContent string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// First member: STORE (no compression) so data is raw bytes we can corrupt.
	fh := &zip.FileHeader{Name: "corrupt.txt", Method: zip.Store}
	f, err := w.CreateHeader(fh)
	require.NoError(t, err)
	_, err = f.Write([]byte(corruptContent))
	require.NoError(t, err)

	// Second member: intact, contains the pattern we must detect.
	f2, err := w.Create("intact.txt")
	require.NoError(t, err)
	_, err = f2.Write([]byte(intactContent))
	require.NoError(t, err)

	require.NoError(t, w.Close())

	data := buf.Bytes()

	// Locate the first local file entry's data and corrupt one byte so the
	// CRC-32 check fails when the zip reader reaches EOF of that entry.
	//
	// Local file header layout (little-endian):
	//   0-3:   signature (PK\x03\x04)
	//   4-5:   version needed
	//   6-7:   flags
	//   8-9:   compression method
	//   10-11: mod time
	//   12-13: mod date
	//   14-17: CRC-32
	//   18-21: compressed size
	//   22-25: uncompressed size
	//   26-27: filename length
	//   28-29: extra field length
	//   30+:   filename, then data
	require.Equal(t, []byte{0x50, 0x4b, 0x03, 0x04}, data[0:4], "expected local file header signature")
	filenameLen := int(binary.LittleEndian.Uint16(data[26:28]))
	extraLen := int(binary.LittleEndian.Uint16(data[28:30]))
	dataOffset := 30 + filenameLen + extraLen
	require.Greater(t, len(data), dataOffset, "zip buffer too short to contain first member's data")
	// Flip a bit so the stored bytes no longer match the CRC in the central directory.
	data[dataOffset] ^= 0xff

	return data
}

// TestArchiveHandler_CorruptedZIPFirstMemberContinuesScanning is the regression
// for https://github.com/trufflesecurity/trufflehog/issues/5403.
//
// A ZIP whose first member has a bad checksum must not stop TruffleHog from
// scanning the remaining intact members. Before the fix, extractorHandler
// propagated the per-member error back to archives.Extract, which halted the
// entire extraction and silently missed subsequent members.
func TestArchiveHandler_CorruptedZIPFirstMemberContinuesScanning(t *testing.T) {
	const pattern = "AKIAYVP4CIPPH5TNP3SW"
	data := corruptedZIPWithIntactSecondMember(t, "this content will fail its CRC check", pattern+" intact content")

	ctx := logContext.AddLogger(context.Background())
	handler := newArchiveHandler()

	rdr, err := newFileReader(ctx, bytes.NewReader(data))
	require.NoError(t, err)
	defer func() { _ = rdr.Close() }()

	dataOrErrChan := handler.HandleFile(ctx, rdr)

	var chunks [][]byte
	var nonFatalErrs []error
	for doe := range dataOrErrChan {
		if doe.Err != nil {
			assert.False(t, errors.Is(doe.Err, ErrProcessingFatal),
				"corrupted member should not produce a fatal error: %v", doe.Err)
			nonFatalErrs = append(nonFatalErrs, doe.Err)
		}
		if len(doe.Data) > 0 {
			chunks = append(chunks, doe.Data)
		}
	}

	// The corrupted member must produce a non-fatal warning, not silence.
	assert.NotEmpty(t, nonFatalErrs, "expected a non-fatal warning for the corrupted member")

	// The intact second member must still be scanned and its content delivered.
	found := false
	for _, c := range chunks {
		if bytes.Contains(c, []byte(pattern)) {
			found = true
			break
		}
	}
	assert.True(t, found, "expected intact ZIP member to be scanned after corrupted first member")
}
