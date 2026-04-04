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

// tessdataDir returns the tessdata directory to use, preferring tessdata-best
// models when available. Resolution order:
//  1. TESSDATA_PREFIX environment variable (explicit user override)
//  2. ~/.tessdata-best (conventional install location for tessdata-best)
//  3. Empty string → let Tesseract use its compiled-in default
func tessdataDir() string {
	if v := os.Getenv("TESSDATA_PREFIX"); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".tessdata-best")
		if _, err := os.Stat(filepath.Join(p, "eng.traineddata")); err == nil {
			return p
		}
	}
	return ""
}

// ocrImage extracts text from a single image using Tesseract.
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

	args := []string{tmpFile.Name(), "stdout", "--oem", "1", "--psm", "6", "--dpi", "300",
		"-c", "preserve_interword_spaces=1",
		"-c", "textord_space_size_is_variable=0",
		// Restrict to printable ASCII — secrets are always ASCII and this prevents
		// Tesseract from substituting Unicode lookalikes (curly quotes, em-dash, etc.)
		// which would cause secret patterns to fail to match.
		"-c", `tessedit_char_whitelist= !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_` + "`" + `abcdefghijklmnopqrstuvwxyz{|}~`,
	}
	if dir := tessdataDir(); dir != "" {
		args = append(args, "--tessdata-dir", dir)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "tesseract", args...)
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

const preprocessScaleFactor = 3

// preprocessImage prepares a screenshot for Tesseract OCR of typed/code text.
//
// Pipeline:
//  1. Convert to grayscale (ITU-R BT.601 luminance).
//  2. Stretch contrast so the full 0–255 range is used.
//  3. Upscale 3× with bilinear interpolation — more pixels per character
//     stroke lets Tesseract resolve details that distinguish l/1/I and 0/O.
//  4. Binarize with Otsu's method — eliminates anti-aliasing gray zones that
//     cause similar-character confusions like L→1 or 9→0.
//  5. Auto-invert if the background is dark (terminal/dark-theme screenshots)
//     because Tesseract's LSTM engine expects dark text on a light background.
//
// Falls back gracefully — callers should use the original data if this errors.
func preprocessImage(data []byte) ([]byte, error) {
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decoding image: %w", err)
	}

	bounds := src.Bounds()
	srcW, srcH := bounds.Dx(), bounds.Dy()

	// Step 1: grayscale at original resolution.
	gray := image.NewGray(image.Rect(0, 0, srcW, srcH))
	for y := 0; y < srcH; y++ {
		for x := 0; x < srcW; x++ {
			r, g, b, _ := src.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
			// ITU-R BT.601 luminance.
			lum := (19595*r + 38470*g + 7471*b + 1<<15) >> 24
			gray.SetGray(x, y, color.Gray{Y: uint8(lum)})
		}
	}

	// Step 2: contrast normalization — stretch histogram to full 0–255 range.
	gray = normalizeContrast(gray, srcW, srcH)

	// Step 3: upscale with bilinear interpolation.
	dstW, dstH := srcW*preprocessScaleFactor, srcH*preprocessScaleFactor
	scaled := image.NewGray(image.Rect(0, 0, dstW, dstH))
	for y := 0; y < dstH; y++ {
		for x := 0; x < dstW; x++ {
			scaled.SetGray(x, y, color.Gray{Y: bilinearSample(gray, srcW, srcH, x, y, dstW, dstH)})
		}
	}

	// Step 4 & 5: Otsu binarization + auto-invert for dark backgrounds.
	thresh := otsuThreshold(scaled, dstW, dstH)
	out := binarizeAndNormalizeBg(scaled, thresh, dstW, dstH)

	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		return nil, fmt.Errorf("encoding preprocessed image: %w", err)
	}
	return buf.Bytes(), nil
}

// normalizeContrast stretches the grayscale histogram so the darkest pixel
// becomes 0 and the brightest becomes 255, maximising contrast before scaling.
func normalizeContrast(img *image.Gray, w, h int) *image.Gray {
	lo, hi := uint8(255), uint8(0)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := img.GrayAt(x, y).Y
			if v < lo {
				lo = v
			}
			if v > hi {
				hi = v
			}
		}
	}
	if hi == lo {
		return img // flat image, nothing to stretch
	}
	scale := 255.0 / float64(hi-lo)
	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := img.GrayAt(x, y).Y
			out.SetGray(x, y, color.Gray{Y: uint8(float64(v-lo) * scale)})
		}
	}
	return out
}

// bilinearSample maps a destination pixel back to fractional source coordinates
// and interpolates between the four surrounding source pixels.
func bilinearSample(img *image.Gray, srcW, srcH, dstX, dstY, dstW, dstH int) uint8 {
	fx := float64(dstX) * float64(srcW-1) / float64(dstW-1)
	fy := float64(dstY) * float64(srcH-1) / float64(dstH-1)

	x0, y0 := int(fx), int(fy)
	x1, y1 := x0+1, y0+1
	if x1 >= srcW {
		x1 = srcW - 1
	}
	if y1 >= srcH {
		y1 = srcH - 1
	}
	dx, dy := fx-float64(x0), fy-float64(y0)

	v00 := float64(img.GrayAt(x0, y0).Y)
	v10 := float64(img.GrayAt(x1, y0).Y)
	v01 := float64(img.GrayAt(x0, y1).Y)
	v11 := float64(img.GrayAt(x1, y1).Y)

	return uint8(v00*(1-dx)*(1-dy) + v10*dx*(1-dy) + v01*(1-dx)*dy + v11*dx*dy)
}

// otsuThreshold computes the optimal binarization threshold using Otsu's method,
// which maximises inter-class variance between foreground and background pixels.
func otsuThreshold(img *image.Gray, w, h int) uint8 {
	total := w * h
	var hist [256]int
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			hist[img.GrayAt(x, y).Y]++
		}
	}

	sum := 0
	for i, c := range hist {
		sum += i * c
	}

	var sumB, wB int
	var best float64
	thresh := uint8(128)
	for i, c := range hist {
		wB += c
		if wB == 0 {
			continue
		}
		wF := total - wB
		if wF == 0 {
			break
		}
		sumB += i * c
		mB := float64(sumB) / float64(wB)
		mF := float64(sum-sumB) / float64(wF)
		v := float64(wB) * float64(wF) * (mB - mF) * (mB - mF)
		if v > best {
			best = v
			thresh = uint8(i)
		}
	}
	return thresh
}

// binarizeAndNormalizeBg converts img to pure black-and-white using thresh, then
// inverts the result if the background is dark so that Tesseract always receives
// dark text on a white background (its preferred input for the LSTM engine).
func binarizeAndNormalizeBg(img *image.Gray, thresh uint8, w, h int) *image.Gray {
	out := image.NewGray(image.Rect(0, 0, w, h))
	lightPx := 0
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if img.GrayAt(x, y).Y >= thresh {
				out.SetGray(x, y, color.Gray{Y: 255})
				lightPx++
			}
		}
	}
	// If more than half the pixels are dark, the background is dark (e.g. a
	// terminal screenshot). Invert so text becomes dark on a white background.
	if lightPx < w*h/2 {
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				if out.GrayAt(x, y).Y == 0 {
					out.SetGray(x, y, color.Gray{Y: 255})
				} else {
					out.SetGray(x, y, color.Gray{Y: 0})
				}
			}
		}
	}
	return out
}
