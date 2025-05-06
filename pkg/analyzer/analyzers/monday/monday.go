package monday

import (
	"errors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

type SecretInfo struct {
	User      Me
	Account   Account
	Resources []MondayResource
}

func (s *SecretInfo) appendResource(resource MondayResource) {
	s.Resources = append(s.Resources, resource)
}

type MondayResource struct {
	ID       string
	Name     string
	Type     string
	MetaData map[string]string
	Parent   *MondayResource
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeMonday
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	_, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}

	return nil, nil
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	return nil, nil
}
