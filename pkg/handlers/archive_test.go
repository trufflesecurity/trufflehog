package handlers

import (
	"bytes"
	"context"
	"encoding/binary"
	regexp "github.com/wasilibs/go-re2"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/bodgit/sevenzip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	return sevenZipFile(append(data.Bytes(), unused...), h)
}

// sevenZipFile wraps packed stream data and an unencoded 7z header in the
// signature header that points at it.
func sevenZipFile(packed, header []byte) []byte {
	start := make([]byte, 20)
	binary.LittleEndian.PutUint64(start[0:], uint64(len(packed)))
	binary.LittleEndian.PutUint64(start[8:], uint64(len(header)))
	binary.LittleEndian.PutUint32(start[16:], crc32.ChecksumIEEE(header))

	out := []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4}
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(start))
	out = append(out, start...)
	out = append(out, packed...)
	return append(out, header...)
}

// append7zNumber appends v in the 7z variable-length number encoding. The
// count of leading one bits in the first byte gives the number of
// little-endian bytes that follow, and the rest of the first byte holds the
// value's highest bits.
func append7zNumber(b []byte, v uint64) []byte {
	for extra := 0; extra < 8; extra++ {
		if v < 1<<(7*(extra+1)) {
			b = append(b, ^byte(0xFF>>extra)|byte(v>>(8*extra)))
			for i := 0; i < extra; i++ {
				b = append(b, byte(v>>(8*i)))
			}
			return b
		}
	}
	b = append(b, 0xFF)
	return binary.LittleEndian.AppendUint64(b, v)
}

// sevenZipEntry is one file stored alone in its own folder and decoded by a
// single coder, so its packed and unpacked sizes are those of the folder.
type sevenZipEntry struct {
	name     string
	methodID []byte
	props    []byte
	packed   []byte
	unpacked uint64
}

// sevenZipArchive builds a 7z archive holding the given entries. The coder
// method, properties and unpack size of each entry are written as given, so
// the header can declare values that a real compressor would not produce.
func sevenZipArchive(entries []sevenZipEntry) []byte {
	n := uint64(len(entries))
	var packed []byte

	h := []byte{0x01, 0x04, 0x06, 0} // Header, MainStreamsInfo, PackInfo at position 0
	h = append7zNumber(h, n)
	h = append(h, 0x09) // pack stream sizes
	for _, e := range entries {
		packed = append(packed, e.packed...)
		h = append7zNumber(h, uint64(len(e.packed)))
	}
	h = append(h, 0x00, 0x07, 0x0B) // end of PackInfo, UnpackInfo, folders
	h = append7zNumber(h, n)
	h = append(h, 0) // folders are stored inline
	for _, e := range entries {
		// One coder per folder. The flag byte holds the method ID length
		// and, when the coder has properties, bit 0x20.
		flag := byte(len(e.methodID))
		if len(e.props) > 0 {
			flag |= 0x20
		}
		h = append(h, 1, flag)
		h = append(h, e.methodID...)
		if len(e.props) > 0 {
			h = append7zNumber(h, uint64(len(e.props)))
			h = append(h, e.props...)
		}
	}
	h = append(h, 0x0C) // folder unpack sizes
	for _, e := range entries {
		h = append7zNumber(h, e.unpacked)
	}
	h = append(h, 0x00, 0x08, 0x0D) // end of UnpackInfo, SubStreamsInfo, files per folder
	for range entries {
		h = append(h, 1)
	}
	h = append(h, 0x00, 0x00, 0x05) // end of SubStreamsInfo, end of MainStreamsInfo, FilesInfo
	h = append7zNumber(h, n)

	var names bytes.Buffer
	names.WriteByte(0) // names are stored inline
	for _, e := range entries {
		for _, u := range utf16.Encode([]rune(e.name + "\x00")) {
			_ = binary.Write(&names, binary.LittleEndian, u)
		}
	}
	h = append(h, 0x11)
	h = append7zNumber(h, uint64(names.Len()))
	h = append(h, names.Bytes()...)
	h = append(h, 0x00, 0x00) // end of FilesInfo, end of Header

	return sevenZipFile(packed, h)
}

// handleArchive runs the archive handler over data and collects the content
// of every chunk it emits along with every error.
func handleArchive(t *testing.T, data []byte) (chunks [][]byte, errs []error) {
	t.Helper()
	ctx := logContext.Background()
	rdr, err := newFileReader(ctx, io.NopCloser(bytes.NewReader(data)))
	require.NoError(t, err)
	defer func() { _ = rdr.Close() }()

	for dataOrErr := range newArchiveHandler().HandleFile(ctx, rdr) {
		if dataOrErr.Err != nil {
			errs = append(errs, dataOrErr.Err)
			continue
		}
		chunks = append(chunks, dataOrErr.Data)
	}
	return chunks, errs
}

// TestArchiveHandler7zCoders extracts archives written by 7-Zip with each of
// the coders that sevenzip_coders.go replaces. The expected content comes from
// the CRC-32 of each file recorded in the archive header, so it does not
// depend on the decoders under test.
func TestArchiveHandler7zCoders(t *testing.T) {
	for _, name := range []string{"ppmd.7z", "lzma.7z", "lzma2.7z"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", name))
			require.NoError(t, err)

			r, err := sevenzip.NewReader(bytes.NewReader(data), int64(len(data)))
			require.NoError(t, err)
			var want []uint32
			for _, f := range r.File {
				if !f.FileInfo().IsDir() {
					want = append(want, f.CRC32)
				}
			}
			require.NotEmpty(t, want)

			chunks, errs := handleArchive(t, data)
			assert.Empty(t, errs)
			var got []uint32
			for _, c := range chunks {
				got = append(got, crc32.ChecksumIEEE(c))
			}
			assert.ElementsMatch(t, want, got)
		})
	}
}

// TestArchiveHandler7zContinuesPastRefusedEntry checks that an entry whose
// coder declares more memory than maxCoderMemory is reported as a warning and
// that the entries after it are still scanned.
func TestArchiveHandler7zContinuesPastRefusedEntry(t *testing.T) {
	const declared = 512 << 20 // above maxCoderMemory, below the handler's file size limit
	tests := []struct {
		name     string
		methodID []byte
		props    []byte
	}{
		{"ppmd", ppmdMethodID, binary.LittleEndian.AppendUint32([]byte{6}, declared)},
		{"lzma", lzmaMethodID, binary.LittleEndian.AppendUint32([]byte{0x5d}, declared)},
		{"lzma2", lzma2MethodID, []byte{lzma2DictProp39}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := sevenZipArchive([]sevenZipEntry{
				{name: "a.txt", methodID: tt.methodID, props: tt.props, packed: make([]byte, 16), unpacked: declared},
				{name: "b.txt", methodID: []byte{0x00}, packed: []byte("file b\n"), unpacked: 7},
			})

			chunks, errs := handleArchive(t, archive)
			require.Len(t, errs, 1)
			assert.ErrorIs(t, errs[0], ErrProcessingWarning)
			assert.ErrorContains(t, errs[0], "exceeds limit")
			require.Len(t, chunks, 1)
			assert.Equal(t, "file b\n", string(chunks[0]))
		})
	}
}

// TestArchiveHandler7zLargeDeclaredDictionary checks that an LZMA2 entry
// declaring a dictionary far above maxCoderMemory still extracts when the
// data it holds is small.
func TestArchiveHandler7zLargeDeclaredDictionary(t *testing.T) {
	content := []byte("file a\n")
	archive := sevenZipArchive([]sevenZipEntry{{
		name:     "a.txt",
		methodID: lzma2MethodID,
		props:    []byte{lzma2DictProp39},
		packed:   encodeLZMA2(t, content),
		unpacked: uint64(len(content)),
	}})

	chunks, errs := handleArchive(t, archive)
	assert.Empty(t, errs)
	require.Len(t, chunks, 1)
	assert.Equal(t, content, chunks[0])
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
