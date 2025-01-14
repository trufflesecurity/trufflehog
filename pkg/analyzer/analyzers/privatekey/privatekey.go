package privatekey

import (
	"errors"
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/privatekey"
	"golang.org/x/crypto/ssh"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypePrivateKey }

func (a Analyzer) Analyze(ctx context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, errors.New("key not found in credInfo")
	}

	info, err := AnalyzePermissions(ctx, a.Cfg, key)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

type SecretInfo struct{}

func AnalyzePermissions(ctx context.Context, cfg *config.Config, key string) (*SecretInfo, error) {
	key = privatekey.Normalize(key)

	parsedKey, err := ssh.ParseRawPrivateKey([]byte(key))
	if err != nil {
		// TODO: check if the key is encrypted
		return nil, err
	}

	fingerprint, err := privatekey.FingerprintPEMKey(parsedKey)
	if err != nil {
		return nil, err
	}

	result, err := privatekey.LookupFingerprint(ctx, fingerprint, true)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%v\n", result)

	return nil, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(context.Background(), cfg, key)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(info)
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType:       analyzers.AnalyzerTypePrivateKey,
		Metadata:           nil,
		Bindings:           nil,
		UnboundedResources: nil,
	}

	return &result
}
