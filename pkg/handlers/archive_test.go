package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestArchiveHandler(t *testing.T) {
	tests := map[string]struct {
		archiveURL     string
		expectedChunks int
		matchString    string
		expectErr      bool
	}{
		"gzip-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/one-zip.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
			false,
		},
		"gzip-nested": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/double-zip.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
			false,
		},
		"gzip-too-deep": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/six-zip.gz",
			0,
			"",
			true,
		},
		"tar-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/one.tar",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
			false,
		},
		"tar-nested": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/two.tar",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
			false,
		},
		"tar-too-deep": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/six.tar",
			0,
			"",
			true,
		},
		"targz-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/tar-archive.tar.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
			false,
		},
		"gzip-large": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/FifteenMB.gz",
			1543,
			"AKIAYVP4CIPPH5TNP3SW",
			false,
		},
		"zip-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
			false,
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Get(testCase.archiveURL)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			defer func() { _ = resp.Body.Close() }()

			handler := newArchiveHandler()

			newReader, err := newFileReader(context.Background(), resp.Body)
			if err != nil {
				t.Errorf("error creating reusable reader: %s", err)
			}
			defer func() { _ = newReader.Close() }()

			dataOrErrChan := handler.HandleFile(logContext.Background(), newReader)
			if testCase.expectErr {
				assert.NoError(t, err)
				return
			}

			count := 0
			re := regexp.MustCompile(testCase.matchString)
			matched := false
			for chunk := range dataOrErrChan {
				count++
				if re.Match(chunk.Data) {
					matched = true
				}
			}

			assert.True(t, matched)
			assert.Equal(t, testCase.expectedChunks, count)
		})
	}
}

func TestOpenInvalidArchive(t *testing.T) {
	reader := strings.NewReader("invalid archive")

	ctx := logContext.AddLogger(context.Background())
	handler := archiveHandler{}

	rdr, err := newFileReader(ctx, io.NopCloser(reader))
	assert.NoError(t, err)
	defer func() { _ = rdr.Close() }()

	dataOrErrChan := make(chan DataOrErr)

	err = handler.openArchive(ctx, 0, rdr, dataOrErrChan)
	assert.Error(t, err)
}

// zipWithStoredMember builds a two-member zip: one stored (uncompressed)
// member and one deflated member carrying a recognizable payload. When corrupt
// is true, one byte inside the stored member's payload is flipped after the
// archive is written, leaving all zip metadata valid but breaking the member's
// CRC, so reading that member fails with a checksum error while its sibling
// stays readable.
func zipWithStoredMember(t *testing.T, corruptFirst bool, corrupt bool) (raw []byte, goodPayload string) {
	t.Helper()
	const (
		badName  = "bad.txt"
		goodName = "intact.txt"
	)
	goodPayload = "canary content that must still be scanned"
	badPayload := strings.Repeat("corruptible-payload ", 16)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name, payload string, method uint16) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		require.NoError(t, err)
		_, err = w.Write([]byte(payload))
		require.NoError(t, err)
	}
	if corruptFirst {
		write(badName, badPayload, zip.Store)
		write(goodName, goodPayload, zip.Deflate)
	} else {
		write(goodName, goodPayload, zip.Deflate)
		write(badName, badPayload, zip.Store)
	}
	require.NoError(t, zw.Close())

	raw = buf.Bytes()
	if !corrupt {
		return raw, goodPayload
	}

	idx := bytes.Index(raw, []byte(badPayload))
	require.NotEqual(t, -1, idx, "stored payload must appear verbatim in the archive")
	raw[idx] ^= 0xFF

	// Sanity check: the corrupted member must now fail with a checksum error
	// while the sibling remains intact.
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	require.NoError(t, err)
	for _, f := range zr.File {
		rc, err := f.Open()
		require.NoError(t, err)
		content, readErr := io.ReadAll(rc)
		_ = rc.Close()
		switch f.Name {
		case badName:
			require.Error(t, readErr, "corrupted member must fail on read")
		case goodName:
			require.NoError(t, readErr)
			require.Equal(t, goodPayload, string(content))
		}
	}
	return raw, goodPayload
}

// A corrupt member must not abort extraction of the whole archive: the intact
// sibling is still scanned, and the skipped member is reported as a non-fatal
// error on the channel. Covers both member orderings.
func TestArchiveHandlerSkipsCorruptMember(t *testing.T) {
	for _, corruptFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("corruptFirst=%v", corruptFirst), func(t *testing.T) {
			raw, goodPayload := zipWithStoredMember(t, corruptFirst, true)

			ctx := logContext.AddLogger(context.Background())
			rdr, err := newFileReader(ctx, bytes.NewReader(raw))
			require.NoError(t, err)
			defer func() { _ = rdr.Close() }()

			handler := newArchiveHandler()
			var goodChunks int
			var memberErrs []error
			for d := range handler.HandleFile(logContext.Background(), rdr) {
				if d.Err != nil {
					memberErrs = append(memberErrs, d.Err)
					continue
				}
				if strings.Contains(string(d.Data), goodPayload) {
					goodChunks++
				}
			}

			assert.Equal(t, 1, goodChunks, "intact member must still be scanned")
			require.Len(t, memberErrs, 1, "the skipped member must be reported exactly once")
			assert.Contains(t, memberErrs[0].Error(), "bad.txt")
			assert.False(t, isFatal(memberErrs[0]), "member errors must not abort processing")
		})
	}
}

// HandleFile must report the scan-coverage gap to the caller: an archive that
// was only partially scanned returns a non-nil error once processing completes,
// while a healthy archive still returns nil.
func TestHandleFileCorruptArchiveMember(t *testing.T) {
	t.Run("corrupt member", func(t *testing.T) {
		raw, goodPayload := zipWithStoredMember(t, true, true)

		ch := make(chan *sources.Chunk, 513)
		err := HandleFile(logContext.Background(), bytes.NewReader(raw), &sources.Chunk{}, sources.ChanReporter{Ch: ch})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bad.txt")

		var found bool
		for len(ch) > 0 {
			chunk := <-ch
			if strings.Contains(string(chunk.Data), goodPayload) {
				found = true
			}
		}
		assert.True(t, found, "intact member chunks must still reach the reporter")
	})

	t.Run("healthy archive", func(t *testing.T) {
		raw, _ := zipWithStoredMember(t, true, false)

		reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 513)}
		assert.NoError(t, HandleFile(logContext.Background(), bytes.NewReader(raw), &sources.Chunk{}, reporter))
	})
}
