package repositorykey

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	urlPat      = regexp.MustCompile(detectors.PrefixRegex([]string{"azure", "url"}) + `([a-z0-9][a-z0-9-]{0,48}[a-z0-9]\.scm\.azure-api\.net)`)
	passwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure", "password"}) + `\b(git&[0-9]{12}&[a-zA-Z0-9\/+]{85}[a-zA-Z0-9]==)`)

	invalidHosts  = simple.NewCache[struct{}]()
	noSuchHostErr = errors.New("Could not resolve host")
)

const (
	azureGitUsername = "apim"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure", ".scm.azure-api.net"}
}

// FromData will find and optionally verify AzureDevopsPersonalAccessToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("azurecr")
	dataStr := string(data)

	// Deduplicate matches.
	uniqueUrlsMatches := make(map[string]struct{})
	uniquePasswordMatches := make(map[string]struct{})

	for _, matches := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueUrlsMatches[strings.TrimSpace(matches[1])] = struct{}{}
	}

	for _, matches := range passwordPat.FindAllStringSubmatch(dataStr, -1) {
		uniquePasswordMatches[strings.TrimSpace(matches[1])] = struct{}{}
	}

EndpointLoop:
	for urlMatch := range uniqueUrlsMatches {
		for passwordMatch := range uniquePasswordMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureApiManagementRepositoryKey,
				Raw:          []byte(passwordMatch),
				RawV2:        []byte(urlMatch + passwordMatch),
			}

			if verify {
				if invalidHosts.Exists(urlMatch) {
					logger.V(3).Info("Skipping invalid registry", "url", urlMatch)
					continue EndpointLoop
				}

				isVerified, err := verifyUrlPassword(ctx, urlMatch, azureGitUsername, passwordMatch)
				s1.Verified = isVerified
				if err != nil {
					if errors.Is(err, noSuchHostErr) {
						invalidHosts.Set(urlMatch, struct{}{})
						continue EndpointLoop
					}
					s1.SetVerificationError(err, urlMatch)
				}
			}
			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureApiManagementRepositoryKey
}

func (s Scanner) Description() string {
	return "Azure API Management Repository Keys provide access to the API Management (APIM) configuration repository, allowing users to directly interact with and modify API definitions, policies, and settings. These keys enable programmatic access to APIM's Git-based repository, where configurations can be cloned, edited, and pushed back to apply changes. They are primarily used for managing API configurations as code, automating deployments, and synchronizing APIM settings across environments."
}

func gitCmdCheck() error {
	if errors.Is(exec.Command("git").Run(), exec.ErrNotFound) {
		return fmt.Errorf("'git' command not found in $PATH. Make sure git is installed and included in $PATH")
	}

	// Check the version is greater than or equal to 2.20.0
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		return fmt.Errorf("failed to check git version: %w", err)
	}

	// Extract the version string using a regex to find the version numbers
	var regex = regexp.MustCompile(`\d+\.\d+\.\d+`)

	versionStr := regex.FindString(string(out))
	versionParts := strings.Split(versionStr, ".")

	// Parse version numbers
	major, _ := strconv.Atoi(versionParts[0])
	minor, _ := strconv.Atoi(versionParts[1])

	// Compare with version 2.20.0<=x<3.0.0
	if major == 2 && minor >= 20 {
		return nil
	}
	return fmt.Errorf("git version is %s, but must be greater than or equal to 2.20.0, and less than 3.0.0", versionStr)
}

func verifyUrlPassword(_ context.Context, repoUrl, user, password string) (bool, error) {
	if err := gitCmdCheck(); err != nil {
		return false, err
	}

	parsedURL, err := url.Parse(repoUrl)
	if err != nil {
		return false, err
	}

	if parsedURL.User == nil {
		parsedURL.User = url.UserPassword(user, password)
	}
	parsedURL.Scheme = "https" // Force HTTPS

	fakeRef := "TRUFFLEHOG_CHECK_GIT_REMOTE_URL_REACHABILITY"
	gitArgs := []string{"ls-remote", parsedURL.String(), "--quiet", fakeRef}
	cmd := exec.Command("git", gitArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputString := string(output)
		if strings.Contains(outputString, "Authentication failed") {
			return false, nil
		} else if strings.Contains(outputString, "Could not resolve host") {
			return false, noSuchHostErr
		}
		return false, err
	}

	return true, nil
}
