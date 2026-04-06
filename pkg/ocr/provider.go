package ocr

import (
	"context"
	"fmt"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/configpb"
)

// Provider extracts text from a preprocessed PNG image.
// imageData is always PNG-encoded bytes produced by the preprocessing pipeline.
type Provider interface {
	ExtractText(ctx context.Context, imageData []byte) (string, error)
}

// ExpandEnv replaces ${VAR} and $VAR occurrences in s with the corresponding
// environment variable values, identical to os.ExpandEnv.
func ExpandEnv(s string) string {
	return os.ExpandEnv(s)
}

// ProviderName returns a human-readable name for the provider described by cfg,
// suitable for log output.
func ProviderName(cfg *configpb.OCRConfig) string {
	if cfg == nil {
		return "tesseract"
	}
	switch cfg.GetProvider().(type) {
	case *configpb.OCRConfig_Tesseract:
		return "tesseract"
	case *configpb.OCRConfig_Google:
		return "google"
	case *configpb.OCRConfig_Openai:
		return "openai"
	case *configpb.OCRConfig_Custom:
		return "custom"
	default:
		return "unknown"
	}
}

// NewProvider builds the correct Provider from a protobuf OCRConfig.
// If cfg is nil the TesseractProvider is returned so that --enable-ocr without
// an explicit config block continues to work exactly as before.
func NewProvider(cfg *configpb.OCRConfig) (Provider, error) {
	if cfg == nil {
		return &TesseractProvider{}, nil
	}

	switch cfg.GetProvider().(type) {
	case *configpb.OCRConfig_Tesseract:
		return &TesseractProvider{}, nil

	case *configpb.OCRConfig_Google:
		return NewGoogleProvider(cfg.GetGoogle())

	case *configpb.OCRConfig_Openai:
		return NewOpenAIProvider(cfg.GetOpenai())

	case *configpb.OCRConfig_Custom:
		return NewCustomHTTPProvider(cfg.GetCustom())

	default:
		return nil, fmt.Errorf("unknown OCR provider in config")
	}
}
