package anthropic

import (
	"errors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg config.Config
}

// SecretInfo hold the information about the anthropic key
type SecretInfo struct {
	Valid              bool
	Type               bool // key type - TODO: Handle Anthropic Admin Keys
	Reference          string
	AnthropicResources []AnthropicResource
	Permissions        string // always full_access
	Misc               map[string]string
}

// AnthropicResource is any resource that can be accessed with anthropic key
type AnthropicResource struct {
	ID       string
	Name     string
	Type     string
	Metadata map[string]string
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerAnthropic
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}

	return nil, nil
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// create a HTTP client
	client := analyzers.NewAnalyzeClient(cfg)

	var secret = &SecretInfo{}

	return nil, nil
}
