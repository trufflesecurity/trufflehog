package config

import (
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/protoyaml"
	"gopkg.in/yaml.v2"
)

// Config holds user supplied configuration.
type Config struct {
	Detectors []detectors.Detector
}

type RawConfig struct {
	Custom *custom_detectorspb.CustomDetectors
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
	var rawConfig RawConfig
	var messages *custom_detectorspb.CustomDetectors
	err := yaml.UnmarshalStrict(input, &rawConfig)
	messages = rawConfig.Custom
	if err != nil {
		// Parse the raw YAML into a structure.
		messages = &custom_detectorspb.CustomDetectors{}
		if err := protoyaml.UnmarshalStrict(input, messages); err != nil {
			return nil, err
		}
	}
	d, err := createDetectors(messages)
	if err != nil {
		return nil, err
	}
	return &Config{
		Detectors: d,
	}, nil
}

func createDetectors(messages *custom_detectorspb.CustomDetectors) ([]detectors.Detector, error) {
	// Convert the structured YAML into detectors.
	var d []detectors.Detector
	for _, detectorConfig := range messages.Detectors {
		detector, err := custom_detectors.NewWebhookCustomRegex(detectorConfig)
		if err != nil {
			return nil, err
		}
		d = append(d, detector)
	}
	return d, nil
}
