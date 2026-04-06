package ocr

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// TesseractProvider extracts text using the local Tesseract binary.
// It is the default provider when --enable-ocr is set without an ocr config block.
type TesseractProvider struct{}

// ExtractText writes imageData (PNG) to a temp file and runs Tesseract on it.
func (p *TesseractProvider) ExtractText(ctx context.Context, imageData []byte) (string, error) {
	if _, err := exec.LookPath("tesseract"); err != nil {
		return "", fmt.Errorf("tesseract not found in PATH: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "trufflehog-ocr-*.png")
	if err != nil {
		return "", fmt.Errorf("error creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(imageData); err != nil {
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
