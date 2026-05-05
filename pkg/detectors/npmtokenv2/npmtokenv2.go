package npmtokenv2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (s Scanner) Version() int { return 2 }

var (
	client = detectors.DetectorHttpClientWithNoLocalAddresses

	keyPat = regexp.MustCompile(`(npm_[0-9a-zA-Z]{36})`)
	
	// Match .npmrc format: //registry.example.com/:_authToken=token
	// (?m) enables multiline mode, ^ ensures line start, \s excludes newlines
	npmrcPat = regexp.MustCompile(`(?m)^//([^/\s]+(?:/[^:\s]+)*)/:_authToken\s*=\s*[^\s]+`)
)

func (s Scanner) Keywords() []string {
	return []string{"npm_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	
	var registrySet map[string]struct{}
	if verify {
		registrySet = extractRegistries(dataStr)
	}

	for _, match := range matches {
		resMatch := match[1]

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_NpmToken,
			Raw:          []byte(resMatch),
			RawV2:        []byte(resMatch),
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/npm/",
		}

		if verify {
			registries := []string{"registry.npmjs.org"}
			if len(registrySet) > 0 {
				registries = make([]string, 0, len(registrySet))
				for reg := range registrySet {
					registries = append(registries, reg)
				}
			}

			isVerified, verificationErr := verifyToken(ctx, resMatch, registries)
			s1.Verified = isVerified
			if isVerified {
				s1.SecretParts = map[string]string{
					"key": resMatch,
				}
			} else if verificationErr != nil {
				s1.SetVerificationError(verificationErr, resMatch)
			}
		}

		results = append(results, s1)
	}

	return
}

func extractRegistries(data string) map[string]struct{} {
	matches := npmrcPat.FindAllStringSubmatch(data, -1)
	registrySet := make(map[string]struct{})
	
	for _, match := range matches {
		if len(match) > 1 {
			registry := strings.TrimSpace(match[1])
			registrySet[registry] = struct{}{}
		}
	}
	
	return registrySet
}

func verifyToken(ctx context.Context, token string, registries []string) (bool, error) {
	var verificationErr error
	sawUnauthorized := false

	for _, registry := range registries {
		registryURL, err := buildRegistryURL(registry)
		if err != nil {
			verificationErr = err
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "GET", registryURL, nil)
		if err != nil {
			verificationErr = err
			continue
		}
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
		res, err := client.Do(req)
		if err != nil {
			verificationErr = err
			continue
		}

		statusCode := res.StatusCode
		res.Body.Close()

		switch statusCode {
		case http.StatusOK:
			return true, nil
		case http.StatusUnauthorized:
			// Track that we saw 401, but continue trying other registries
			sawUnauthorized = true
		default:
			verificationErr = fmt.Errorf("unexpected HTTP response status %d", statusCode)
		}
	}

	// If we tried all registries and at least one returned 401 (and none succeeded),
	// the token is definitively invalid
	if sawUnauthorized {
		return false, nil
	}

	return false, verificationErr
}

func buildRegistryURL(registry string) (string, error) {
	registry = strings.TrimSpace(registry)
	registry = strings.TrimSuffix(registry, "/")
	
	var baseURL *url.URL
	var err error
	
	if strings.HasPrefix(registry, "http://") || strings.HasPrefix(registry, "https://") {
		baseURL, err = url.Parse(registry)
	} else {
		baseURL, err = url.Parse("https://" + registry)
	}
	
	if err != nil {
		return "", err
	}
	
	// Append /-/whoami to the path
	if baseURL.Path == "" {
		baseURL.Path = "/-/whoami"
	} else {
		baseURL.Path = baseURL.Path + "/-/whoami"
	}
	
	return baseURL.String(), nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NpmToken
}

func (s Scanner) Description() string {
	return "NPM tokens are used to authenticate and publish packages to the NPM registry."
}
