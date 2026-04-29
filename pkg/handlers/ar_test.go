package handlers

import (
	stdctx "context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pault.ag/go/debian/deb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestHandleARFile(t *testing.T) {
	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	assert.NoError(t, err)
	defer rdr.Close()

	handler := newARHandler()
	dataOrErrChan := handler.HandleFile(context.AddLogger(ctx), rdr)
	assert.NoError(t, err)

	wantChunkCount := 102
	count := 0
	for range dataOrErrChan {
		count++
	}

	assert.Equal(t, wantChunkCount, count)
}

// stagedReaderAt is an io.ReaderAt that serves a fixed AR header region from
// head and returns bodyErr for any read inside the first entry's data section.
// Reads past the first entry return io.EOF so deb.Ar.Next reports a clean end
// of archive on the iteration after the failure, letting processARFiles return
// without an extra wrapped error masking the one we want to assert on.
type stagedReaderAt struct {
	head     []byte
	bodySize int64
	bodyErr  error
}

func (s *stagedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	headLen := int64(len(s.head))
	switch {
	case off < headLen:
		n := copy(p, s.head[off:])
		if n < len(p) {
			// Caller wants bytes that span into the body; surface the body error.
			return n, s.bodyErr
		}
		return n, nil
	case off < headLen+s.bodySize:
		return 0, s.bodyErr
	default:
		return 0, io.EOF
	}
}

// arHeaderForEntry builds the AR magic plus a single 60-byte entry header
// declaring the given size. The deb library accepts space-padded fields and
// requires the trailing 0x60 0x0A magic, which is what this fixture provides.
func arHeaderForEntry(size int64) []byte {
	const magic = "!<arch>\n"
	header := make([]byte, 60)
	for i := range header {
		header[i] = ' '
	}
	copy(header[0:16], "evil.dat/")
	copy(header[16:28], "0")
	copy(header[28:34], "0")
	copy(header[34:40], "0")
	copy(header[40:48], "100644")
	copy(header[48:58], fmt.Sprintf("%d", size))
	header[58] = 0x60
	header[59] = 0x0A
	return append([]byte(magic), header...)
}

// TestARHandler_MimeTypeReaderErrPreservesIdentity is a regression test for
// the %v wrap at ar.go:101. Before the fix, wrapping the inner error returned
// from newMimeTypeReader with %v dropped its identity from the errors.Is
// chain, which let isFatal misclassify a context-cancelled or
// deadline-exceeded read on the underlying source io.Reader as a non-fatal
// warning. The reachability path is bufReader.Peek -> io.SectionReader over
// the deb library's reader -> BufferedReadSeeker.ReadAt -> the original
// source io.Reader passed to HandleFile, where HTTP/GCS-backed source readers
// surface parent-context cancellation as a Read error whose chain satisfies
// errors.Is(err, context.DeadlineExceeded).
//
// io.EOF is filtered inside newMimeTypeReader (handlers.go:95), so it never
// reaches the wrap site at ar.go:101. The non-fatal column uses
// io.ErrUnexpectedEOF instead, which is the closest analogue that the wrap
// site can actually observe.
func TestARHandler_MimeTypeReaderErrPreservesIdentity(t *testing.T) {
	cases := []struct {
		name      string
		innerErr  error
		wantFatal bool
	}{
		{
			name:      "context.DeadlineExceeded is fatal",
			innerErr:  stdctx.DeadlineExceeded,
			wantFatal: true,
		},
		{
			name:      "context.Canceled is fatal",
			innerErr:  stdctx.Canceled,
			wantFatal: true,
		},
		{
			name:      "io.ErrUnexpectedEOF is non-fatal",
			innerErr:  io.ErrUnexpectedEOF,
			wantFatal: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const bodySize int64 = 4096
			raa := &stagedReaderAt{
				head:     arHeaderForEntry(bodySize),
				bodySize: bodySize,
				bodyErr:  tc.innerErr,
			}

			arReader, err := deb.LoadAr(raa)
			require.NoError(t, err)

			handler := newARHandler()
			dataOrErrChan := make(chan DataOrErr, defaultBufferSize)
			go func() {
				defer close(dataOrErrChan)
				_ = handler.processARFiles(context.Background(), arReader, dataOrErrChan)
			}()

			var warnErr error
			for d := range dataOrErrChan {
				if d.Err != nil && errors.Is(d.Err, ErrProcessingWarning) {
					warnErr = d.Err
					break
				}
			}
			require.Error(t, warnErr, "expected wrapped warning from ar.go mime-type reader path")

			assert.True(t, errors.Is(warnErr, ErrProcessingWarning),
				"outer ErrProcessingWarning wrap should be preserved")
			assert.True(t, errors.Is(warnErr, tc.innerErr),
				"inner cause should be inspectable via errors.Is")
			assert.Equal(t, tc.wantFatal, isFatal(warnErr),
				"isFatal should classify based on the inner cause")
		})
	}
}
