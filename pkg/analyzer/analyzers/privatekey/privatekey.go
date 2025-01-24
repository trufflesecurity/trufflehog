package privatekey

import (
	"errors"
	"fmt"
	"strings"
	"sync"

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

type SecretInfo struct {
	TLSCertificateResult *privatekey.DriftwoodResult
	GithubUsername       *string
	GitlabUsername       *string
}

func AnalyzePermissions(ctx context.Context, cfg *config.Config, key string) (*SecretInfo, error) {
	token := privatekey.Normalize(key)
	if len(token) < 64 {
		return nil, fmt.Errorf("invalid token")
	}

	var (
		wg                 sync.WaitGroup
		parsedKey          any
		err                error
		verificationErrors = privatekey.NewVerificationErrors(3)
		info               = &SecretInfo{}
	)

	parsedKey, err = ssh.ParseRawPrivateKey([]byte(token))
	if err != nil && strings.Contains(err.Error(), "private key is passphrase protected") {
		// key is password protected
		parsedKey, _, err = privatekey.Crack([]byte(token))
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	fingerprint, err := privatekey.FingerprintPEMKey(parsedKey)
	if err != nil {
		return nil, err
	}

	// Look up certificate information.
	wg.Add(1)
	go func() {
		defer wg.Done()
		data, err := privatekey.LookupFingerprint(ctx, fingerprint)
		if err != nil {
			verificationErrors.Add(err)
		} else {
			info.TLSCertificateResult = data
		}
	}()

	// Test SSH key against github.com
	wg.Add(1)
	go func() {
		defer wg.Done()
		user, err := privatekey.VerifyGitHubUser(ctx, parsedKey)
		if err != nil {
			verificationErrors.Add(err)
		} else if user != nil {
			info.GithubUsername = user
		}
	}()

	// Test SSH key against gitlab.com
	wg.Add(1)
	go func() {
		defer wg.Done()
		user, err := privatekey.VerifyGitLabUser(ctx, parsedKey)
		if err != nil {
			verificationErrors.Add(err)
		} else if user != nil {
			info.GitlabUsername = user
		}
	}()
	wg.Wait()

	if len(verificationErrors.Errors) > 0 {
		return nil, fmt.Errorf("verification failures: %s", strings.Join(verificationErrors.Errors, ", "))
	}

	return info, nil
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
