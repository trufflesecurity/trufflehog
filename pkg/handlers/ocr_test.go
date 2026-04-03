package handlers

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

func skipIfNoTesseract(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tesseract"); err != nil {
		t.Skip("tesseract not found in PATH, skipping OCR test")
	}
}

func skipIfNoFFmpeg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not found in PATH, skipping video OCR test")
	}
}

// TestOCRHandlerImage verifies that the OCR handler extracts text from an image.
// Expects testdata/test_secret.png to contain visible text (e.g., a fake AWS key).
func TestOCRHandlerImage(t *testing.T) {
	skipIfNoTesseract(t)
	feature.EnableOCR.Store(true)
	defer feature.EnableOCR.Store(false)

	file, err := os.Open("testdata/test_secret.png")
	require.NoError(t, err)
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	require.NoError(t, err)
	defer rdr.Close()

	handler := newOCRHandler()
	dataOrErrChan := handler.HandleFile(context.AddLogger(ctx), rdr)

	count := 0
	for dataOrErr := range dataOrErrChan {
		if dataOrErr.Err != nil {
			t.Logf("received error: %v", dataOrErr.Err)
			continue
		}
		count++
		assert.NotEmpty(t, dataOrErr.Data)
	}

	assert.Greater(t, count, 0, "expected at least one chunk of OCR text from test_secret.png")
}

// TestOCRHandlerImageNoText verifies that a blank image produces no chunks.
// Expects testdata/test_no_text.png to be an image with no readable text.
func TestOCRHandlerImageNoText(t *testing.T) {
	skipIfNoTesseract(t)
	feature.EnableOCR.Store(true)
	defer feature.EnableOCR.Store(false)

	file, err := os.Open("testdata/test_no_text.png")
	require.NoError(t, err)
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	require.NoError(t, err)
	defer rdr.Close()

	handler := newOCRHandler()
	dataOrErrChan := handler.HandleFile(context.AddLogger(ctx), rdr)

	count := 0
	for dataOrErr := range dataOrErrChan {
		if dataOrErr.Err != nil {
			continue
		}
		count++
	}

	assert.Equal(t, 0, count, "expected no chunks from a blank image")
}

// TestOCRHandlerDisabled verifies that the handler produces no output when the feature flag is off.
func TestOCRHandlerDisabled(t *testing.T) {
	feature.EnableOCR.Store(false)

	file, err := os.Open("testdata/test_secret.png")
	require.NoError(t, err)
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	require.NoError(t, err)
	defer rdr.Close()

	handler := newOCRHandler()
	dataOrErrChan := handler.HandleFile(context.AddLogger(ctx), rdr)

	count := 0
	for range dataOrErrChan {
		count++
	}

	assert.Equal(t, 0, count, "expected no chunks when OCR is disabled")
}

// TestOCRHandlerVideo verifies that the OCR handler extracts text from video frames.
// Expects testdata/test_secret.webm to be a short video with visible text in at least one frame.
func TestOCRHandlerVideo(t *testing.T) {
	skipIfNoTesseract(t)
	skipIfNoFFmpeg(t)
	feature.EnableOCR.Store(true)
	defer feature.EnableOCR.Store(false)

	file, err := os.Open("testdata/test_secret.webm")
	require.NoError(t, err)
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	require.NoError(t, err)
	defer rdr.Close()

	handler := newOCRHandler()
	dataOrErrChan := handler.HandleFile(context.AddLogger(ctx), rdr)

	count := 0
	for dataOrErr := range dataOrErrChan {
		if dataOrErr.Err != nil {
			t.Logf("received error: %v", dataOrErr.Err)
			continue
		}
		count++
		assert.NotEmpty(t, dataOrErr.Data)
	}

	assert.Greater(t, count, 0, "expected at least one chunk of OCR text from test_secret.webm")
}

// TestOCRMimeTypeRouting verifies that selectHandler routes image/video MIME types
// to the OCR handler when the feature flag is enabled, and to the default handler when disabled.
func TestOCRMimeTypeRouting(t *testing.T) {
	tests := []struct {
		name       string
		mime       mimeType
		ocrEnabled bool
		wantOCR    bool
	}{
		{"png with OCR enabled", pngMime, true, true},
		{"jpeg with OCR enabled", jpegMime, true, true},
		{"mp4 with OCR enabled", mp4Mime, true, true},
		{"mkv with OCR enabled", mkvMime, true, true},
		{"webm with OCR enabled", webmMime, true, true},
		{"png with OCR disabled", pngMime, false, false},
		{"jpeg with OCR disabled", jpegMime, false, false},
		{"mp4 with OCR disabled", mp4Mime, false, false},
		{"text/plain always default", textMime, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feature.EnableOCR.Store(tt.ocrEnabled)
			defer feature.EnableOCR.Store(false)

			handler := selectHandler(tt.mime, false)
			_, isOCR := handler.(*ocrHandler)
			assert.Equal(t, tt.wantOCR, isOCR)
		})
	}
}
