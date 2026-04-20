package handlers

import (
	"archive/zip"
	"bytes"
	stdCtx "context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/iobuf"
)

func TestAPKHandler(t *testing.T) {
	tests := map[string]struct {
		archiveURL      string
		expectedChunks  int
		expectedSecrets int
		matchString     string
	}{
		"apk_with_3_leaked_keys": {
			archiveURL:     "https://raw.githubusercontent.com/trufflesecurity/leakyAPK/main/aws_leak.apk",
			expectedChunks: 942,
			// Note: the secret count is 4 instead of 3 b/c we're not actually running the secret detection engine,
			// we're just looking for a string match. There is one extra string match in the APK (but only 3 detected secrets).
			expectedSecrets: 4,
			matchString:     "AKIA2UC3BSXMLSCLTUUS",
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Get(testCase.archiveURL)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			defer resp.Body.Close()

			handler := newAPKHandler()

			newReader, err := newFileReader(context.Background(), resp.Body)
			if err != nil {
				t.Errorf("error creating reusable reader: %s", err)
			}
			defer newReader.Close()

			archiveChan := handler.HandleFile(context.Background(), newReader)

			chunkCount := 0
			secretCount := 0
			re := regexp.MustCompile(testCase.matchString)
			matched := false
			for chunk := range archiveChan {
				chunkCount++
				if re.Match(chunk.Data) {
					secretCount++
					matched = true
				}
			}

			assert.True(t, matched)
			// The APK handler's chunk count may increase over time as new keywords are added
			// as the default detector list grows. We use GreaterOrEqual to ensure the test remains
			// stable while allowing for this expected growth.
			assert.GreaterOrEqual(t, chunkCount, testCase.expectedChunks)
			assert.Equal(t, testCase.expectedSecrets, secretCount)
		})
	}
}

func TestOpenInvalidAPK(t *testing.T) {
	reader := strings.NewReader("invalid apk")

	ctx := context.AddLogger(context.Background())
	handler := apkHandler{}

	rdr, err := newFileReader(ctx, io.NopCloser(reader))
	assert.NoError(t, err)
	defer rdr.Close()

	archiveChan := make(chan DataOrErr)

	err = handler.processAPK(ctx, rdr, archiveChan)
	assert.Contains(t, err.Error(), "zip: not a valid zip file")
}

func TestOpenValidZipInvalidAPK(t *testing.T) {
	// Grabbed from archive_test.go
	validZipURL := "https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip"

	resp, err := http.Get(validZipURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	handler := newAPKHandler()

	newReader, err := newFileReader(context.Background(), resp.Body)
	if err != nil {
		t.Errorf("error creating reusable reader: %s", err)
	}
	assert.NoError(t, err)
	defer newReader.Close()

	archiveChan := make(chan DataOrErr)
	ctx := context.AddLogger(context.Background())

	err = handler.processAPK(ctx, newReader, archiveChan)
	assert.Contains(t, err.Error(), "resources.arsc file not found")
}

// buildMinimalAPK creates a zip archive containing a minimal valid resources.arsc
// (empty resource table with 0 packages) and the specified number of dummy XML files.
func buildMinimalAPK(t *testing.T, fileCount int) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Minimal resources.arsc: RES_TABLE_TYPE header with 0 packages.
	w, err := zw.Create("resources.arsc")
	if err != nil {
		t.Fatal(err)
	}
	resArsc := []byte{
		0x02, 0x00, // id = RES_TABLE_TYPE
		0x0c, 0x00, // headerSize = 12
		0x0c, 0x00, 0x00, 0x00, // totalSize = 12
		0x00, 0x00, 0x00, 0x00, // packageCount = 0
	}
	if _, err := w.Write(resArsc); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < fileCount; i++ {
		fw, err := zw.Create(fmt.Sprintf("res/layout/file_%04d.xml", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("<xml>data</xml>")); err != nil {
			t.Fatal(err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProcessAPK_ExitsOnContextCancellation(t *testing.T) {
	apkData := buildMinimalAPK(t, 500)

	rdr := iobuf.NewBufferedReaderSeeker(bytes.NewReader(apkData))
	defer rdr.Close()

	handler := newAPKHandler()
	apkChan := make(chan DataOrErr, defaultBufferSize)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := handler.processAPK(context.AddLogger(ctx), fileReader{BufferedReadSeeker: rdr}, apkChan)
	if err != stdCtx.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestProcessAPK_ExitsOnDeadlineExceeded(t *testing.T) {
	apkData := buildMinimalAPK(t, 500)

	rdr := iobuf.NewBufferedReaderSeeker(bytes.NewReader(apkData))
	defer rdr.Close()

	handler := newAPKHandler()
	apkChan := make(chan DataOrErr, defaultBufferSize)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	err := handler.processAPK(context.AddLogger(ctx), fileReader{BufferedReadSeeker: rdr}, apkChan)
	if err != stdCtx.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
}
