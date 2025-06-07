package config

import (
	"fmt"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/configpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/protoyaml"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/docker"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/filesystem"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/gcs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/gitlab"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/jenkins"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/postman"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/s3"
)

// Config holds user supplied configuration.
type Config struct {
	Sources   []sources.ConfiguredSource
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
	var inputYAML configpb.Config
	// Parse the raw YAML into a structure.
	if err := protoyaml.UnmarshalStrict(input, &inputYAML); err != nil {
		return nil, err
	}

	// Convert to detectors.
	var detectorConfigs []detectors.Detector
	for _, detectorConfig := range inputYAML.Detectors {
		detector, err := custom_detectors.NewWebhookCustomRegex(detectorConfig)
		if err != nil {
			return nil, err
		}
		detectorConfigs = append(detectorConfigs, detector)
	}

	// Convert to configured sources.
	var sourceConfigs []sources.ConfiguredSource
	for _, pbSource := range inputYAML.Sources {
		s, err := instantiateSourceFromType(pbSource.GetType())
		if err != nil {
			return nil, err
		}
		src := sources.NewConfiguredSource(s, pbSource)

		sourceConfigs = append(sourceConfigs, src)
	}

	return &Config{
		Detectors: detectorConfigs,
		Sources:   sourceConfigs,
	}, nil
}

// instantiateSourceFromType creates a concrete implementation of
// sources.Source for the provided type.
func instantiateSourceFromType(sourceType string) (sources.Source, error) {
	var source sources.Source
	switch sourceType {
	case sourcespb.SourceType_SOURCE_TYPE_GIT.String():
		source = new(git.Source)
	case sourcespb.SourceType_SOURCE_TYPE_GITHUB.String():
		source = new(github.Source)
	case sourcespb.SourceType_SOURCE_TYPE_GITHUB_UNAUTHENTICATED_ORG.String():
		source = new(github.Source)
	case sourcespb.SourceType_SOURCE_TYPE_PUBLIC_GIT.String():
		source = new(git.Source)
	case sourcespb.SourceType_SOURCE_TYPE_GITLAB.String():
		source = new(gitlab.Source)
	case sourcespb.SourceType_SOURCE_TYPE_POSTMAN.String():
		source = new(postman.Source)
	case sourcespb.SourceType_SOURCE_TYPE_S3.String():
		source = new(s3.Source)
	case sourcespb.SourceType_SOURCE_TYPE_S3_UNAUTHED.String():
		source = new(s3.Source)
	case sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM.String():
		source = new(filesystem.Source)
	case sourcespb.SourceType_SOURCE_TYPE_JENKINS.String():
		source = new(jenkins.Source)
	case sourcespb.SourceType_SOURCE_TYPE_GCS.String():
		source = new(gcs.Source)
	case sourcespb.SourceType_SOURCE_TYPE_GCS_UNAUTHED.String():
		source = new(gcs.Source)
	case sourcespb.SourceType_SOURCE_TYPE_DOCKER.String():
		source = new(docker.Source)
	default:
		return nil, fmt.Errorf("got unexpected source type: %q", sourceType)
	}

	return source, nil
}
