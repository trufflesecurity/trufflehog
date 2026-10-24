package handlers

import (
	"bytes"
	"context"
	"encoding/binary"
	regexp "github.com/wasilibs/go-re2"
	"hash/crc32"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
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

// sevenZipWithEmptyFolder builds an uncompressed 7z archive with two folders.
// The first folder holds the given files. The second folder declares zero
// unpack streams, which is valid 7z: libarchive lists such an archive without
// error. Older 7z readers panicked with an index out of range while parsing
// this header.
func sevenZipWithEmptyFolder(files []string) []byte {
	var data bytes.Buffer
	for _, f := range files {
		data.WriteString(f)
	}
	unused := "unused\n"

	var names bytes.Buffer
	names.WriteByte(0) // names are stored inline
	for i := range files {
		for _, u := range utf16.Encode([]rune(string(rune('a'+i)) + ".txt\x00")) {
			_ = binary.Write(&names, binary.LittleEndian, u)
		}
	}

	// Every count and size below is under 0x80, so each fits the one-byte
	// form of the 7z variable-length number encoding.
	h := []byte{
		0x01,       // Header
		0x04,       // MainStreamsInfo
		0x06, 0, 2, // PackInfo: position 0, two pack streams
		0x09, byte(data.Len()), byte(len(unused)), // pack stream sizes
		0x00,          // end of PackInfo
		0x07, 0x0B, 2, // UnpackInfo: two folders
		0,          // folders are stored inline
		1, 0x01, 0, // folder 1: one Copy coder
		1, 0x01, 0, // folder 2: one Copy coder
		0x0C, byte(data.Len()), byte(len(unused)), // folder unpack sizes
		0x00,                         // end of UnpackInfo
		0x08, 0x0D, byte(len(files)), // SubStreamsInfo: files in folder 1
		0, // folder 2 holds no files
		0x09,
	}
	for _, f := range files[:len(files)-1] {
		h = append(h, byte(len(f))) // sizes of all but the last file in folder 1
	}
	h = append(h,
		0x00,                   // end of SubStreamsInfo
		0x00,                   // end of MainStreamsInfo
		0x05, byte(len(files)), // FilesInfo
		0x11, byte(names.Len()), // file names
	)
	h = append(h, names.Bytes()...)
	h = append(h, 0x00, 0x00) // end of FilesInfo, end of Header

	start := make([]byte, 20)
	binary.LittleEndian.PutUint64(start[0:], uint64(data.Len()+len(unused)))
	binary.LittleEndian.PutUint64(start[8:], uint64(len(h)))
	binary.LittleEndian.PutUint32(start[16:], crc32.ChecksumIEEE(h))

	out := []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4}
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(start))
	out = append(out, start...)
	out = append(out, data.Bytes()...)
	out = append(out, unused...)
	return append(out, h...)
}

func TestArchiveHandler7zEmptyFolder(t *testing.T) {
	files := make([]string, 8)
	for i := range files {
		files[i] = "file " + string(rune('a'+i)) + "\n"
	}

	ctx := logContext.Background()
	rdr, err := newFileReader(ctx, io.NopCloser(bytes.NewReader(sevenZipWithEmptyFolder(files))))
	assert.NoError(t, err)
	defer func() { _ = rdr.Close() }()

	var got []string
	for dataOrErr := range newArchiveHandler().HandleFile(ctx, rdr) {
		assert.NoError(t, dataOrErr.Err)
		got = append(got, string(dataOrErr.Data))
	}
	assert.ElementsMatch(t, files, got)
}

func TestArchiveHandlerRar5ZeroHeaderSize(t *testing.T) {
	// A RAR 5 signature followed by a block header that declares a size of
	// zero. Older rar readers sliced past the end of the header buffer here.
	data := []byte("Rar!\x1a\x07\x01\x00" + "\x00\x00\x00\x00" + "\x00" + "\x00\x00")

	ctx := logContext.Background()
	rdr, err := newFileReader(ctx, io.NopCloser(bytes.NewReader(data)))
	assert.NoError(t, err)
	defer func() { _ = rdr.Close() }()

	for dataOrErr := range newArchiveHandler().HandleFile(ctx, rdr) {
		if dataOrErr.Err != nil {
			assert.NotContains(t, dataOrErr.Err.Error(), "panic")
		}
	}
}
