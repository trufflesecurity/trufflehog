package npmtoken

import (
	"context"
	"fmt"
	"net/http"
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
	
	npmrcPat = regexp.MustCompile(`//([^/]+(?:/[^:]+)*)/:_authToken\s*=\s*([^\s]+)`)
)

func (s Scanner) Keywords() []string {
	return []string{"npm"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	
	var tokenRegistryMap map[string]string
	if verify {
		tokenRegistryMap = extractTokenRegistryPairs(dataStr)
	}
	
	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_NpmToken,
			Raw:          []byte(resMatch),
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/npm/",
		}

		if verify {
			registry, found := tokenRegistryMap[resMatch]
			if !found {
				registry = "registry.npmjs.org"
			}
			
			isVerified, extraData := verifyToken(ctx, resMatch, registry)
			s1.Verified = isVerified
			if isVerified {
				s1.AnalysisInfo = extraData
			}
		}

		results = append(results, s1)
	}

	return
}

func extractTokenRegistryPairs(data string) map[string]string {
	matches := npmrcPat.FindAllStringSubmatch(data, -1)
	tokenMap := make(map[string]string)
	
	for _, match := range matches {
		if len(match) > 2 {
			registry := match[1]
			token := match[2]
			
			token = strings.TrimSpace(token)
			if _, exists := tokenMap[token]; !exists {
				tokenMap[token] = registry
			}
		}
	}
	
	return tokenMap
}

func verifyToken(ctx context.Context, token string, registry string) (bool, map[string]string) {
	registryURL := buildRegistryURL(registry)
	
	req, err := http.NewRequestWithContext(ctx, "GET", registryURL, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return true, map[string]string{
				"key":      token,
				"registry": registry,
			}
		}
	}
	
	return false, nil
}

func buildRegistryURL(registry string) string {
	registry = strings.TrimSpace(registry)
	registry = strings.TrimSuffix(registry, "/")
	
	if strings.HasPrefix(registry, "http://") || strings.HasPrefix(registry, "https://") {
		return registry + "/-/whoami"
	}
	
	return "https://" + registry + "/-/whoami"
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NpmToken
}

func (s Scanner) Description() string {
	return "NPM tokens are used to authenticate and publish packages to the npm registry."
}
