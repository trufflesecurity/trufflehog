package npmtoken

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

func (s Scanner) Version() int { return 1 }

var (
	client = detectors.DetectorHttpClientWithNoLocalAddresses

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"npm"}) + `\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	
	npmrcPat = regexp.MustCompile(`//([^/]+(?:/[^:]+)*)/:_authToken\s*=\s*[^\s]+`)
)

func (s Scanner) Keywords() []string {
	return []string{"npm"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	
	var registrySet map[string]struct{}
	if verify {
		registrySet = extractRegistries(dataStr)
	}
	
	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_NpmToken,
			Raw:          []byte(resMatch),
			RawV2:        []byte(resMatch),
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/npm/",
		}

		if verify {
			registry := "registry.npmjs.org"
			if len(registrySet) > 0 {
				// Use the first registry found, or default to npmjs
				for reg := range registrySet {
					registry = reg
					break
				}
			}
			
			verificationErr := verifyToken(ctx, resMatch, registry)
			if verificationErr == nil {
				s1.Verified = true
				s1.AnalysisInfo = map[string]string{
					"key":      resMatch,
					"registry": registry,
				}
			} else {
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

func verifyToken(ctx context.Context, token string, registry string) error {
	registryURL, err := buildRegistryURL(registry)
	if err != nil {
		return err
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", registryURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}
	
	return fmt.Errorf("verification failed with status code %d", res.StatusCode)
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
	return "NPM tokens are used to authenticate and publish packages to the npm registry."
}
