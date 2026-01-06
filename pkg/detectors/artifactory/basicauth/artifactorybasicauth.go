package artifactory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
}

type basicArtifactoryCredential struct {
	username string
	password string
	host     string
	raw      string
}

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)

	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	basicAuthURLPattern = regexp.MustCompile(
		`https?://(?P<username>[^:@\s]+):(?P<password>[^@\s]+)@(?P<host>[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]\.jfrog\.io)(?P<path>/[^\s"'<>]*)?`,
	)

	invalidHosts = simple.NewCache[struct{}]()

	errNoHost = errors.New("no such host")
)


// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"artifactory", "jfrog.io"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Artifactory secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// ----------------------------------------
	// Basic Auth URI detection & verification
	// ----------------------------------------
	basicCreds := make(map[string]basicArtifactoryCredential)

	for _, match := range basicAuthURLPattern.FindAllStringSubmatch(dataStr, -1) {
		if len(match) == 0 {
			continue
		}
		subexpNames := basicAuthURLPattern.SubexpNames()

		var username, password, host string
		for i, name := range subexpNames {
			if i == 0 || name == "" {
				continue
			}
			switch name {
			case "username":
				username = match[i]
			case "password":
				password = match[i]
			case "host":
				host = match[i]
			}
		}

		if username == "" || password == "" || host == "" {
			continue
		}

		key := username + ":" + password + "@" + host
		if _, exists := basicCreds[key]; exists {
			continue
		}

		basicCreds[key] = basicArtifactoryCredential{
			username: username,
			password: password,
			host:     host,
			raw:      match[0],
		}
	}

	for _, cred := range basicCreds {
		if invalidHosts.Exists(cred.host) {
			continue
		}

		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_ArtifactoryAccessToken,
			Raw:          []byte(cred.raw),
			RawV2:        []byte(cred.username + ":" + cred.password + "@" + cred.host),
		}

		if verify {
			isVerified, vErr := verifyArtifactoryBasicAuth(ctx, s.getClient(), cred.host, cred.username, cred.password)
			r.Verified = isVerified

			if vErr != nil {
				if errors.Is(vErr, errNoHost) {
					invalidHosts.Set(cred.host, struct{}{})
					continue
				}
				r.SetVerificationError(vErr, cred.username, cred.host)
			}

			if isVerified {
				if r.AnalysisInfo == nil {
					r.AnalysisInfo = make(map[string]string)
				}
				r.AnalysisInfo["domain"] = cred.host
				r.AnalysisInfo["username"] = cred.username
				r.AnalysisInfo["password"] = cred.password
				r.AnalysisInfo["authType"] = "basic"
			}
		}

		results = append(results, r)
	}

	return results, nil
}

func verifyArtifactoryBasicAuth(ctx context.Context, client *http.Client, host, username, password string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/artifactory/api/system/ping", nil)
	if err != nil {
		return false, err
	}

	// Use HTTP Basic authentication with the parsed username and password.
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoHost
		}

		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		if strings.Contains(string(body), "OK") {
			return true, nil
		}

		return false, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ArtifactoryBasicAuth
}

func (s Scanner) Description() string {
	return "Artifactory is a repository manager that supports all major package formats. Artifactory access tokens can be used to authenticate and perform operations on repositories."
}
