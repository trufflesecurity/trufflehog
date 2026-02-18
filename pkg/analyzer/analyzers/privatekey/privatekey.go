//go:generate generate_permissions permissions.yaml permissions.go privatekey

package privatekey

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
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
	// token will be already normalized by the time it reaches here
	token, ok := credInfo["token"]
	if !ok {
		return nil, analyzers.NewAnalysisError("PrivateKey", "validate_credentials", "config", "", errors.New("token not found in credInfo"))
	}

	info, err := AnalyzePermissions(ctx, a.Cfg, token)
	if err != nil {
		return nil, analyzers.NewAnalysisError("PrivateKey", "analyze_permissions", "crypto", "", err)
	}

	return secretInfoToAnalyzerResult(info), nil
}

type SecretInfo struct {
	TLSCertificateResult *privatekey.DriftwoodResult
	GithubUsername       *string
	GitlabUsername       *string
}

func AnalyzePermissions(ctx context.Context, cfg *config.Config, token string) (*SecretInfo, error) {

	var (
		wg             sync.WaitGroup
		parsedKey      any
		err            error
		analyzerErrors = privatekey.NewVerificationErrors(3)
		info           = &SecretInfo{}
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
		data, err := analyzeFingerprint(ctx, fingerprint)
		if err != nil {
			analyzerErrors.Add(err)
		} else {
			info.TLSCertificateResult = data
		}
	}()

	// Test SSH key against github.com
	wg.Add(1)
	go func() {
		defer wg.Done()
		user, err := analyzeGithubUser(ctx, parsedKey)
		if err != nil {
			analyzerErrors.Add(err)
		} else if user != nil {
			info.GithubUsername = user
		}
	}()

	// Test SSH key against gitlab.com
	wg.Add(1)
	go func() {
		defer wg.Done()
		user, err := analyzeGitlabUser(ctx, parsedKey)
		if err != nil {
			analyzerErrors.Add(err)
		} else if user != nil {
			info.GitlabUsername = user
		}
	}()
	wg.Wait()

	if len(analyzerErrors.Errors) == 3 {
		return nil, fmt.Errorf("analyzer failures: %s", strings.Join(analyzerErrors.Errors, ", "))
	}

	return info, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	if cfg.LoggingEnabled {
		color.Red("[x] Logging is not supported for this analyzer.")
		return
	}

	token := privatekey.Normalize(key)
	if len(token) < 64 {
		color.Red("[x] Error: Invalid Private Key")
		return
	}

	// key entered through command line may have spaces instead of newlines, replace them
	token = replaceSpacesWithNewlines(token)

	info, err := AnalyzePermissions(context.Background(), cfg, token)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	color.Green("[!] Valid Private Key\n\n")

	if info.GithubUsername == nil && info.GitlabUsername == nil && info.TLSCertificateResult == nil {
		color.Yellow("[i] Insufficient information returned from fingerprint analysis. No permissions found.")
		return
	}

	if info.GithubUsername != nil {
		color.Yellow("[i] GitHub Details:")
		printUserInfo(*info.GithubUsername)
	}
	if info.GitlabUsername != nil {
		color.Yellow("[i] GitLab Details:")
		printUserInfo(*info.GitlabUsername)
	}
	if info.TLSCertificateResult != nil {
		printTLSCertificateResult(info.TLSCertificateResult)
	}

}

func printUserInfo(username string) {
	color.Yellow("[i] Username: %s", username)
	color.Yellow("[i] Permissions: %s\n\n", color.GreenString("Clone/Push"))
}

func printTLSCertificateResult(result *privatekey.DriftwoodResult) {
	color.Yellow("[i] TLS Certificate Details:")
	fmt.Print("\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(
		table.Row{"Subject Key ID", "Subject Name", "Subject Organization", "Permissions", "Expiration Date", "Domains"})
	green := color.New(color.FgGreen).SprintFunc()
	for _, certificateResult := range result.CertificateResults {
		t.AppendRow([]interface{}{
			green(certificateResult.SubjectKeyID),
			green(certificateResult.SubjectName),
			green(strings.Join(certificateResult.SubjectOrganization, ", ")),
			green(strings.Join(append(certificateResult.KeyUsages, certificateResult.ExtendedKeyUsages...), ", ")),
			green(certificateResult.ExpirationTimestamp.Format(time.RFC3339)),
			green(strings.Join(certificateResult.Domains, ", ")),
		})
	}
	t.Render()
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType:       analyzers.AnalyzerTypePrivateKey,
		Metadata:           nil,
		Bindings:           []analyzers.Binding{},
		UnboundedResources: []analyzers.Resource{},
	}

	if info.TLSCertificateResult != nil {
		bounded, unbounded := bakeTLSResources(info.TLSCertificateResult)
		result.Bindings = append(result.Bindings, bounded...)
		result.UnboundedResources = append(result.UnboundedResources, unbounded...)
	}

	if info.GithubUsername != nil {
		result.Bindings = append(result.Bindings, bakeGithubResources(info.GithubUsername)...)
	}

	if info.GitlabUsername != nil {
		result.Bindings = append(result.Bindings, bakeGitlabResources(info.GitlabUsername)...)
	}

	return &result
}

func bakeGithubResources(username *string) []analyzers.Binding {
	resource := &analyzers.Resource{
		Name:               *username,
		FullyQualifiedName: fmt.Sprintf("github.com/user/%s", *username),
		Type:               "user", // always user ???
	}

	permissions := []analyzers.Permission{
		{Value: PermissionStrings[Clone], Parent: nil},
		{Value: PermissionStrings[Push], Parent: nil},
	}

	return analyzers.BindAllPermissions(*resource, permissions...)
}

func bakeGitlabResources(username *string) []analyzers.Binding {
	resource := &analyzers.Resource{
		Name:               *username,
		FullyQualifiedName: fmt.Sprintf("gitlab.com/user/%s", *username),
		Type:               "user", // always user ???
	}

	permissions := []analyzers.Permission{
		{Value: PermissionStrings[Clone], Parent: nil},
		{Value: PermissionStrings[Push], Parent: nil},
	}

	return analyzers.BindAllPermissions(*resource, permissions...)
}

func bakeTLSResources(result *privatekey.DriftwoodResult) ([]analyzers.Binding, []analyzers.Resource) {

	unboundedResources := make([]analyzers.Resource, 0, len(result.CertificateResults))
	boundedResources := make([]analyzers.Binding, 0, len(result.CertificateResults))

	// iterate result.CertificateResults
	for _, cert := range result.CertificateResults {
		if cert.SubjectName == "" && cert.SubjectKeyID == "" {
			continue
		}
		resource := &analyzers.Resource{
			Name:               cert.SubjectName,
			FullyQualifiedName: fmt.Sprintf("%s/%s", cert.SubjectKeyID, cert.SubjectName),
			Type:               "certificate",
		}
		certPermissions := append(cert.KeyUsages, cert.ExtendedKeyUsages...)
		permissions := make([]analyzers.Permission, 0, len(certPermissions))
		for _, perm := range certPermissions {
			perm, ok := StringToPermission[perm]
			if !ok {
				continue
			}
			permissions = append(permissions, analyzers.Permission{
				Value:  PermissionStrings[perm],
				Parent: nil,
			})
		}

		if len(permissions) > 0 {
			// bind all permissions with resources
			boundedResources = append(boundedResources, analyzers.BindAllPermissions(*resource, permissions...)...)
		} else {
			unboundedResources = append(unboundedResources, *resource)
		}

	}

	return boundedResources, unboundedResources
}

func analyzeFingerprint(ctx context.Context, fingerprint string) (*privatekey.DriftwoodResult, error) {

	result, err := privatekey.LookupFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, err
	}
	if len(result.CertificateResults) == 0 {
		return nil, nil
	}
	return result, nil
}

func analyzeGithubUser(ctx context.Context, parsedKey any) (*string, error) {
	return privatekey.VerifyGitHubUser(ctx, parsedKey)
}

func analyzeGitlabUser(ctx context.Context, parsedKey any) (*string, error) {
	return privatekey.VerifyGitLabUser(ctx, parsedKey)
}

// replaceSpacesWithNewlines extracts the base64 part, replaces spaces with newlines if needed, and reconstructs the key.
func replaceSpacesWithNewlines(privateKey string) string {
	// Regex pattern to extract the key content
	re := regexp.MustCompile(`(?i)(-----\s*BEGIN[ A-Z0-9_-]*PRIVATE KEY\s*-----)\s*([\s\S]*?)\s*(-----\s*END[ A-Z0-9_-]*PRIVATE KEY\s*-----)`)

	// Find matches
	matches := re.FindStringSubmatch(privateKey)
	if len(matches) != 4 {
		// no need to process
		return privateKey
	}

	header := matches[1]     // BEGIN line
	base64Part := matches[2] // Base64 content
	footer := matches[3]     // END line

	// Replace spaces with newlines
	formattedBase64 := strings.ReplaceAll(base64Part, " ", "\n")

	// Reconstruct the private key
	return fmt.Sprintf("%s\n%s\n%s", header, formattedBase64, footer)
}
