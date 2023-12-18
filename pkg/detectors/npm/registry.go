package npm

import (
	"fmt"
	"regexp"
	"strings"
)

type registryInfo struct {
	Scheme       scheme
	Uri          string
	RegistryType registryType
}

// The scheme of the registry URL.
type scheme int

const (
	unknown scheme = iota
	isHttp
	isHttps
)

func (scheme scheme) String() string {
	return [...]string{
		"unknown",
		"isHttp",
		"isHttps",
	}[scheme]
}

// Prefix returns the HTTP prefix that corresponds to the enum: "", "http://", and "https://" respectively.
func (scheme scheme) Prefix() string {
	return [...]string{
		"",
		"http://",
		"https://",
	}[scheme]
}

// A collection of known registry implementations.
type registryType int

const (
	// Others npm registries include:
	// - https://github.com/verdaccio/verdaccio
	// - https://coding.net/help/docs/ci/practice/artifacts/npm.html
	// - https://www.privjs.com
	other registryType = iota
	npm
	artifactoryCloud
	artifactoryHosted
	nexusRepo2
	nexusRepo3
	gitlab // TODO: Self-hosted GitLab?
	github // TODO: Self-hosted GitHub packages?
	azure
	jetbrains
	googleArtifactRegistry
	gemfury
)

func (t registryType) String() string {
	return [...]string{
		"other",
		"npm",
		"artifactoryCloud",
		"artifactoryHosted",
		"nexusRepo2",
		"nexusRepo3",
		"gitlab",
		"github",
		"azure",
		"jetbrains",
		"googleArtifactRegistry",
		"gemfury",
	}[t]
}

var (
	defaultRegistryInfo = &registryInfo{
		RegistryType: npm,
		Scheme:       isHttps,
		Uri:          "registry.npmjs.org",
	}

	domainPat = `(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}` // this doesn't match single segment hosts (e.g., localhost)
	ipV4Pat   = `(?:[0-9]{1,3}\.){3}[0-9]{1,3}`                        // overly permissive but should be fine in context
	hostPat   = fmt.Sprintf(`(?:%s|%s)(?::\d{1,5})?`, domainPat, ipV4Pat)

	knownRegistryPat = func() *regexp.Regexp {
		var sb strings.Builder
		sb.WriteString(`(?i)((?:https?:)?//)(?:`)
		// `registry.yarnpkg.com` is a reverse-proxy (https://github.com/yarnpkg/yarn/issues/889)
		sb.WriteString(`(registry\.(?:npmjs\.org|yarnpkg\.com))`)
		artifactoryPath := `/(?:artifactory|[a-z0-9._-]+)/api/npm/[a-z][a-z0-9._-]+`
		artifactoryOldPath := `/(?:artifactory|[a-z0-9._-]+)/v\d\.\d/artifacts/[a-z][a-z0-9._-]+`   // appears to be a path from older versions.
		sb.WriteString(`|([a-z0-9-]+\.jfrog\.io` + artifactoryPath + `)`)                           // cloud
		sb.WriteString(fmt.Sprintf(`|(%s(?:%s|%s))`, hostPat, artifactoryPath, artifactoryOldPath)) // hosted
		// https://help.sonatype.com/repomanager2/node-packaged-modules-and-npm-registries
		sb.WriteString(`|(` + hostPat + `/nexus/content/(?:groups|repositories)/[a-z0-9-][a-z0-9._-]+)`)
		// https://help.sonatype.com/repomanager3/nexus-repository-administration/formats/npm-registry/configuring-npm
		sb.WriteString(`|(` + hostPat + `/(?:nexus/)?repository/[a-z0-9-][a-z0-9._-]+)`)
		// https://docs.gitlab.com/ee/user/packages/npm_registry/
		sb.WriteString(`|(` + hostPat + `/api/v4/(?:groups/\d+/-/|projects/\d+/)?packages/npm)`)
		// https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry
		sb.WriteString(`|(npm\.pkg\.github\.com)`)
		// https://learn.microsoft.com/en-us/azure/devops/artifacts/get-started-npm?view=azure-devops&tabs=Windows
		// https://stackoverflow.com/a/73495381
		azurePat := `pkgs\.dev\.azure\.com/[a-z0-9._-]+(?:/[a-z0-9._-]+)?`
		vsPat := `[a-z0-9-]+\.pkgs\.visualstudio\.com(?:/[a-z0-9._-]+)?`
		sb.WriteString(fmt.Sprintf(`|((?:%s|%s)/_packaging/[a-z0-9._-]+/npm(?:/registry)?)`, azurePat, vsPat))
		// https://www.jetbrains.com/help/space/using-an-npm-registry-with-npmjs-com.html
		sb.WriteString(`|(npm\.pkg\.jetbrains\.space/[a-z0-9._-]+/p/[a-z0-9._-]+/[a-z0-9._-]+)`)
		sb.WriteString(`|((?:[a-z0-9-]+-)?npm\.pkg\.dev/[a-z0-9._-]+/[a-z0-9._-]+)`)
		sb.WriteString(`|(npm(?:-proxy)?\.fury\.io/[a-z0-9._-]+)`)
		sb.WriteString(`)`)

		return regexp.MustCompile(sb.String())
	}()
	genericRegistryPat = func() *regexp.Regexp {
		urlPat := fmt.Sprintf(`%s(?:/[a-z0-9._-]+)*`, hostPat)
		registryPat := regexp.MustCompile(fmt.Sprintf(
			`(?i)['"]?(//%s)/:|registry.{1,50}?['"]?(https?://%s)/?['"]?|@[a-z0-9\-_]{1,50}['"]?[ \t]*(?:=[ \t]*)?['"]?(https?://%s)/?['"]?|\[npmAuth\.['"](https?://%s)/?['"]\]`, urlPat, urlPat, urlPat, urlPat))

		// Sanity check to make sure the pattern doesn't contain a mistake.
		if registryPat.NumSubexp() != 4 {
			panic(fmt.Sprintf("Pattern |genericRegistryPat| should have 4 capture groups but has %d", registryPat.NumSubexp()))
		}
		return registryPat
	}()
)

// findTokenRegistry returns the specific registry associated with the |token| if a high confidence match is found in |data|.
//
// Common configurations:
// - npm: https://docs.npmjs.com/using-private-packages-in-a-ci-cd-workflow#create-and-check-in-a-project-specific-npmrc-file
// - Yarn (TODO)
// - Unity Package Manager (TODO)
func findTokenRegistry(data string, token string) *registryInfo {
	// .npmrc stores auth as `//registry.com/path/:authToken=$TOKEN
	// Therefore, we should be able to correlate a token to a registry with a high degree of confidence.
	registryAuthPat := regexp.MustCompile(fmt.Sprintf(
		// language=regexp
		`(?i)(//%s(?:/[a-z0-9._-]+)*)/:(?:_auth(?:Token)?|_password).{1,20}%s`, hostPat, token))
	matches := registryAuthPat.FindStringSubmatch(data)
	if len(matches) == 0 {
		return nil
	}

	// A match was found, attempt to parse it.
	uri := matches[1]
	info := parseKnownRegistryURI(data, uri)
	if info == nil {
		info = parseUnknownRegistryURI(data, uri)
	}
	return info
}

// findAllRegistryURLs returns all instances of URLs that *look like* registries.
// These are not associated with a specific token.
func findAllRegistryURLs(data string) map[string]*registryInfo {
	registries := make(map[string]*registryInfo)

	// Look for known high-confidence matches.
	for _, matches := range knownRegistryPat.FindAllStringSubmatch(data, -1) {
		var (
			_, uri = firstNonEmptyMatch(matches, 2) // first two matches are the entire string and protocol/prefix
			info   = parseKnownRegistryURI(data, matches[1]+uri)
		)
		// Might be unnecessary, |info| is almost guaranteed to not be nil.
		if info == nil {
			continue
		}
		if _, ok := registries[info.Uri]; ok {
			continue
		}

		registries[info.Uri] = info
	}

	// Attempt to parse any other low confidence matches.
	for _, matches := range genericRegistryPat.FindAllStringSubmatch(data, -1) {
		// Skip known registry patterns, those should have already been handled above.
		if knownRegistryPat.MatchString(matches[0]) {
			continue
		}

		_, uri := firstNonEmptyMatch(matches, 1) // first match is the entire string
		info := &registryInfo{
			RegistryType: other,
		}
		info.Scheme, info.Uri = parseRegistryURLScheme(data, uri)
		if _, ok := registries[info.Uri]; ok {
			continue
		}

		registries[info.Uri] = info
	}

	if len(registries) == 0 {
		registries[defaultRegistryInfo.Uri] = defaultRegistryInfo
	}
	return registries
}

// parseKnownRegistryURI
func parseKnownRegistryURI(data string, registryUri string) *registryInfo {
	matches := knownRegistryPat.FindStringSubmatch(registryUri)
	if len(matches) == 0 {
		return nil
	}

	// Skip the first two indices: 1 is the entire string, 2 is the protocol.
	index, uri := firstNonEmptyMatch(matches, 2)
	info := &registryInfo{
		RegistryType: registryType(index - 1),
	}
	info.Scheme, info.Uri = parseRegistryURLScheme(data, uri)

	// Normalize the URI.
	if info.RegistryType == npm && info.Scheme != isHttps {
		info.Scheme = isHttps
	} else if info.RegistryType == artifactoryCloud && info.Scheme != isHttps {
		info.Scheme = isHttps
	} else if info.RegistryType == github && info.Scheme != isHttps {
		info.Scheme = isHttps
	} else if info.RegistryType == azure {
		if info.Scheme != isHttps {
			info.Scheme = isHttps
		}
		if !strings.HasSuffix(strings.ToLower(info.Uri), "/registry") {
			info.Uri = info.Uri + "/registry"
		}
	} else if info.RegistryType == jetbrains && info.Scheme != isHttps {
		info.Scheme = isHttps
	} else if info.RegistryType == googleArtifactRegistry && info.Scheme != isHttps {
		info.Scheme = isHttps
	} else if info.RegistryType == gemfury && info.Scheme != isHttps {
		info.Scheme = isHttps
	}

	return info
}

// parseUnknownRegistryURI
func parseUnknownRegistryURI(data string, registryUri string) *registryInfo {
	scheme, uri := parseRegistryURLScheme(data, registryUri)
	info := &registryInfo{
		RegistryType: other,
		Scheme:       scheme,
		Uri:          uri,
	}
	return info
}

// parseRegistryURLScheme attempts to find the scheme of the provided |uri|.
func parseRegistryURLScheme(data string, uri string) (scheme, string) {
	var (
		scheme           = unknown
		uriWithoutScheme string
	)
	// If the match starts with "http" or "https", we can be confident about the Scheme.
	// Otherwise, it is unknown.
	u := strings.ToLower(uri) // for case-insensitive comparison. Might not be the best way.
	if strings.HasPrefix(u, "https://") {
		scheme = isHttps
		uriWithoutScheme = uri[8:]
	} else if strings.HasPrefix(u, "http://") {
		scheme = isHttp
		uriWithoutScheme = uri[7:]
	} else if strings.HasPrefix(u, "//") {
		uriWithoutScheme = uri[2:]
	} else {
		uriWithoutScheme = uri
	}

	// If the Scheme is unknown, look for other instances of the Uri that might have the Scheme.
	//
	// Scheme    -> registry=https://example.com/repository/npm-proxy/
	// no Scheme -> //example.com/repository/npm-proxy/:_authToken=123456
	if scheme == unknown {
		var (
			uriPat  = regexp.MustCompile(`(?i)(https?)://` + uriWithoutScheme)
			schemes = make(map[string]struct{})
		)
		for _, m := range uriPat.FindAllStringSubmatch(data, -1) {
			schemes[strings.ToLower(m[1])] = struct{}{}
		}
		// Decisively HTTP or HTTPS; nothing or both is equally useless.
		if len(schemes) == 1 {
			if _, ok := schemes["https"]; ok {
				scheme = isHttps
			} else {
				scheme = isHttp
			}
		}
	}
	return scheme, uriWithoutScheme
}
