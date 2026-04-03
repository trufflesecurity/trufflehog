package handlers

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg" // Register JPEG decoder for image.Decode.
	"image/png"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

const (
	maxOCRImageSize      = 50 * 1024 * 1024  // 50 MB
	maxOCRVideoSize      = 500 * 1024 * 1024 // 500 MB
	frameIntervalSeconds = 1                 // Extract 1 frame per second.
)

// ocrHandler extracts text from images and video frames using external
// tools (tesseract for OCR, ffmpeg for video frame extraction) and feeds
// the extracted text into the standard text processing pipeline.
type ocrHandler struct{ *defaultHandler }

var _ FileHandler = (*ocrHandler)(nil)

func newOCRHandler() *ocrHandler {
	return &ocrHandler{defaultHandler: newDefaultHandler(ocrHandlerType)}
}

// HandleFile processes image and video files by extracting text via OCR.
func (h *ocrHandler) HandleFile(ctx logContext.Context, input fileReader) chan DataOrErr {
	dataOrErrChan := make(chan DataOrErr, defaultBufferSize)

	if !feature.EnableOCR.Load() {
		close(dataOrErrChan)
		return dataOrErrChan
	}

	go func() {
		defer close(dataOrErrChan)
		defer func() {
			if r := recover(); r != nil {
				var panicErr error
				if e, ok := r.(error); ok {
					panicErr = e
				} else {
					panicErr = fmt.Errorf("panic occurred: %v", r)
				}
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: panic error: %v", ErrProcessingFatal, panicErr),
				}
			}
		}()

		start := time.Now()

		mimeStr := mimeType(input.mime.String())
		var text string
		var err error

		switch {
		case isImageMime(mimeStr):
			text, err = h.ocrImage(ctx, input)
		case isVideoMime(mimeStr):
			text, err = h.ocrVideo(ctx, input)
		default:
			err = fmt.Errorf("unsupported MIME type for OCR: %s", mimeStr)
		}

		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: OCR processing error: %v", ErrProcessingWarning, err),
			}
			h.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
			return
		}

		if strings.TrimSpace(text) == "" {
			h.measureLatencyAndHandleErrors(ctx, start, nil, dataOrErrChan)
			return
		}

		textReader := mimeTypeReader{
			mimeExt:  ".txt",
			mimeName: textMime,
			Reader:   strings.NewReader(text),
		}

		if err := h.handleNonArchiveContent(ctx, textReader, dataOrErrChan); err != nil {
			h.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
			return
		}

		h.metrics.incFilesProcessed()
		h.measureLatencyAndHandleErrors(ctx, start, nil, dataOrErrChan)
	}()

	return dataOrErrChan
}

// ocrImage extracts text from a single image using tesseract.
func (h *ocrHandler) ocrImage(ctx logContext.Context, input io.Reader) (string, error) {
	if _, err := exec.LookPath("tesseract"); err != nil {
		return "", fmt.Errorf("tesseract not found in PATH: %w", err)
	}

	imgData, err := io.ReadAll(io.LimitReader(input, maxOCRImageSize+1))
	if err != nil {
		return "", fmt.Errorf("error reading image data: %w", err)
	}
	if len(imgData) > maxOCRImageSize {
		ctx.Logger().V(2).Info("skipping image: size exceeds OCR limit", "limit", maxOCRImageSize)
		return "", nil
	}

	processedData, err := preprocessImage(imgData)
	if err != nil {
		ctx.Logger().V(3).Info("image preprocessing failed, using original", "error", err)
		processedData = imgData
	}

	tmpFile, err := os.CreateTemp("", "trufflehog-ocr-*.png")
	if err != nil {
		return "", fmt.Errorf("error creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(processedData); err != nil {
		tmpFile.Close()
		return "", fmt.Errorf("error writing temp file: %w", err)
	}
	tmpFile.Close()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "tesseract",
		tmpFile.Name(), "stdout",
		"--psm", "6",
		"--dpi", "300",
		"-c", "preserve_interword_spaces=1",
		"-c", "textord_space_size_is_variable=0",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("tesseract failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}

// ocrVideo extracts text from video frames using ffmpeg for frame extraction
// and tesseract for OCR on each frame.
func (h *ocrHandler) ocrVideo(ctx logContext.Context, input io.Reader) (string, error) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return "", fmt.Errorf("ffmpeg not found in PATH: %w", err)
	}
	if _, err := exec.LookPath("tesseract"); err != nil {
		return "", fmt.Errorf("tesseract not found in PATH: %w", err)
	}

	videoData, err := io.ReadAll(io.LimitReader(input, maxOCRVideoSize+1))
	if err != nil {
		return "", fmt.Errorf("error reading video data: %w", err)
	}
	if len(videoData) > maxOCRVideoSize {
		ctx.Logger().V(2).Info("skipping video: size exceeds OCR limit", "limit", maxOCRVideoSize)
		return "", nil
	}

	tmpVideo, err := os.CreateTemp("", "trufflehog-ocr-video-*")
	if err != nil {
		return "", fmt.Errorf("error creating temp video file: %w", err)
	}
	defer os.Remove(tmpVideo.Name())

	if _, err := tmpVideo.Write(videoData); err != nil {
		tmpVideo.Close()
		return "", fmt.Errorf("error writing temp video file: %w", err)
	}
	tmpVideo.Close()

	tmpFrameDir, err := os.MkdirTemp("", "trufflehog-ocr-frames-*")
	if err != nil {
		return "", fmt.Errorf("error creating temp frame dir: %w", err)
	}
	defer os.RemoveAll(tmpFrameDir)

	// Extract frames at 1fps.
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-i", tmpVideo.Name(),
		"-vf", fmt.Sprintf("fps=%d", frameIntervalSeconds),
		"-vsync", "vfr",
		filepath.Join(tmpFrameDir, "frame_%04d.png"),
	)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ffmpeg frame extraction failed: %w (stderr: %s)", err, stderr.String())
	}

	frames, err := filepath.Glob(filepath.Join(tmpFrameDir, "frame_*.png"))
	if err != nil {
		return "", fmt.Errorf("error listing extracted frames: %w", err)
	}
	sort.Strings(frames)

	var allText strings.Builder
	for _, framePath := range frames {
		frameFile, err := os.Open(framePath)
		if err != nil {
			ctx.Logger().V(3).Info("skipping frame: unable to open", "path", framePath, "error", err)
			continue
		}

		text, err := h.ocrImage(ctx, frameFile)
		frameFile.Close()
		if err != nil {
			ctx.Logger().V(3).Info("skipping frame: OCR failed", "path", framePath, "error", err)
			continue
		}

		if trimmed := strings.TrimSpace(text); trimmed != "" {
			if allText.Len() > 0 {
				allText.WriteString("\n")
			}
			allText.WriteString(trimmed)
		}
	}

	return allText.String(), nil
}

func isImageMime(m mimeType) bool {
	return m == pngMime || m == jpegMime
}

func isVideoMime(m mimeType) bool {
	return m == mp4Mime || m == mkvMime || m == webmMime
}

const preprocessScaleFactor = 2

// preprocessImage decodes an image, converts it to grayscale, and scales it up
// by 2x to improve tesseract accuracy on small or low-contrast text.
// Falls back gracefully — callers should use the original data if this errors.
func preprocessImage(data []byte) ([]byte, error) {
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decoding image: %w", err)
	}

	bounds := src.Bounds()
	w, h := bounds.Dx()*preprocessScaleFactor, bounds.Dy()*preprocessScaleFactor

	gray := image.NewGray(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		srcY := bounds.Min.Y + y/preprocessScaleFactor
		for x := 0; x < w; x++ {
			srcX := bounds.Min.X + x/preprocessScaleFactor
			r, g, b, _ := src.At(srcX, srcY).RGBA()
			// ITU-R BT.601 luminance.
			lum := (19595*r + 38470*g + 7471*b + 1<<15) >> 24
			gray.SetGray(x, y, color.Gray{Y: uint8(lum)})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, gray); err != nil {
		return nil, fmt.Errorf("encoding preprocessed image: %w", err)
	}
	return buf.Bytes(), nil
}
