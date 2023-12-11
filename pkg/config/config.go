package config

import (
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/protoyaml"
)

// Config holds user supplied configuration.
type Config struct {
	Detectors []detectors.Detector
}

// Read parses a given filename into a Config.
func Read(filename string) (*Config, error) {
	input, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewYAML(input)
}

// NewYAML parses the given YAML data into a Config.
func NewYAML(input []byte) (*Config, error) {
	// Parse the raw YAML into a structure.
	var messages custom_detectorspb.CustomDetectors
	if err := protoyaml.UnmarshalStrict(input, &messages); err != nil {
		return nil, err
	}
	// Convert the structured YAML into detectors.
	var d []detectors.Detector
	for _, detectorConfig := range messages.Detectors {
		detector, err := custom_detectors.NewWebhookCustomRegex(detectorConfig)
		if err != nil {
			return nil, err
		}
		d = append(d, detector)
	}
	return &Config{
		Detectors: d,
	}, nil
}
