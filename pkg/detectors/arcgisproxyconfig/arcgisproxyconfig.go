package arcgisproxyconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const (
	serverURLTagName    = "serverUrl"
	maxServerURLTagSize = 4 * 1024
)

type Scanner struct{}

// Ensure Scanner satisfies the interfaces used for multi-part credentials.
var _ interface {
	detectors.Detector
	detectors.MultiPartCredentialProvider
} = (*Scanner)(nil)

type credential struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain,omitempty"`
}

func (Scanner) Keywords() []string {
	return []string{serverURLTagName}
}

// MaxCredentialSpan allows all components of one bounded serverUrl tag to be
// considered together without combining values from separate XML elements.
func (Scanner) MaxCredentialSpan() int64 {
	return maxServerURLTagSize
}

// FromData finds credentials embedded in ArcGIS resource-proxy serverUrl
// elements. These credentials cannot be safely verified generically: the URL
// can reference an arbitrary self-hosted service, and the expected
// authentication flow varies by deployment. Results therefore remain
// unverified even when verification is requested.
func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	seen := make(map[string]struct{})

	for _, tag := range findServerURLStartTags(data) {
		candidate, ok := parseCredential(tag)
		if !ok {
			continue
		}

		rawV2, err := json.Marshal(candidate)
		if err != nil {
			return results, err
		}
		if _, ok := seen[string(rawV2)]; ok {
			continue
		}
		seen[string(rawV2)] = struct{}{}

		secretParts := map[string]string{
			"url":      candidate.URL,
			"username": candidate.Username,
			"password": candidate.Password,
		}
		if candidate.Domain != "" {
			secretParts["domain"] = candidate.Domain
		}

		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_ArcGISProxyConfig,
			Raw:          []byte(candidate.Password),
			RawV2:        rawV2,
			Redacted:     redact(candidate),
			SecretParts:  secretParts,
		}
		result.SetPrimarySecretValue(candidate.Password)
		results = append(results, result)
	}

	return results, nil
}

func (Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ArcGISProxyConfig
}

func (Scanner) Description() string {
	return "ArcGIS resource-proxy configuration credentials can grant access to protected backend map and feature services."
}

// findServerURLStartTags extracts only bounded XML start tags whose local name
// is serverUrl. It deliberately avoids parsing the whole chunk because source
// chunks commonly contain XML fragments or surrounding non-XML text.
func findServerURLStartTags(data []byte) [][]byte {
	var tags [][]byte
	searchFrom := 0

	for searchFrom < len(data) {
		relativeNameStart := bytes.Index(data[searchFrom:], []byte(serverURLTagName))
		if relativeNameStart < 0 {
			break
		}

		nameStart := searchFrom + relativeNameStart
		searchFrom = nameStart + len(serverURLTagName)

		if !isTagNameEnd(data, searchFrom) {
			continue
		}
		tagStart, ok := findTagStart(data, nameStart)
		if !ok {
			continue
		}
		tagEnd, ok := findTagEnd(data, tagStart)
		if !ok {
			continue
		}

		tags = append(tags, data[tagStart:tagEnd])
	}

	return tags
}

func isTagNameEnd(data []byte, index int) bool {
	if index >= len(data) {
		return false
	}
	switch data[index] {
	case ' ', '\t', '\r', '\n', '/', '>':
		return true
	default:
		return false
	}
}

func findTagStart(data []byte, nameStart int) (int, bool) {
	if nameStart > 0 && data[nameStart-1] == '<' {
		return nameStart - 1, true
	}

	// XML namespaces may express the element as <prefix:serverUrl>.
	if nameStart < 2 || data[nameStart-1] != ':' {
		return 0, false
	}
	index := nameStart - 2
	for index >= 0 && isASCIIXMLNameByte(data[index]) {
		index--
	}
	if index < 0 || data[index] != '<' || index+1 == nameStart-1 {
		return 0, false
	}
	return index, true
}

func isASCIIXMLNameByte(b byte) bool {
	return b == '_' || b == '-' || b == '.' ||
		b >= '0' && b <= '9' ||
		b >= 'A' && b <= 'Z' ||
		b >= 'a' && b <= 'z'
}

func findTagEnd(data []byte, tagStart int) (int, bool) {
	limit := tagStart + maxServerURLTagSize
	if limit > len(data) {
		limit = len(data)
	}

	var quote byte
	for index := tagStart + 1; index < limit; index++ {
		switch {
		case quote != 0 && data[index] == quote:
			quote = 0
		case quote != 0:
			continue
		case data[index] == '\'' || data[index] == '"':
			quote = data[index]
		case data[index] == '>':
			return index + 1, true
		}
	}

	return 0, false
}

func parseCredential(tag []byte) (credential, bool) {
	decoder := xml.NewDecoder(bytes.NewReader(tag))
	token, err := decoder.Token()
	if err != nil {
		return credential{}, false
	}

	element, ok := token.(xml.StartElement)
	if !ok || element.Name.Local != serverURLTagName {
		return credential{}, false
	}

	var candidate credential
	seenAttributes := make(map[string]struct{})
	for _, attribute := range element.Attr {
		// The ArcGIS schema defines these attributes as unqualified. Ignore
		// similarly named attributes from unrelated namespaces.
		if attribute.Name.Space != "" {
			continue
		}

		var destination *string
		switch attribute.Name.Local {
		case "url":
			destination = &candidate.URL
		case "username":
			destination = &candidate.Username
		case "password":
			destination = &candidate.Password
		case "domain":
			destination = &candidate.Domain
		default:
			continue
		}

		if _, duplicate := seenAttributes[attribute.Name.Local]; duplicate {
			return credential{}, false
		}
		seenAttributes[attribute.Name.Local] = struct{}{}
		*destination = attribute.Value
	}

	if !validHTTPURL(candidate.URL) ||
		strings.TrimSpace(candidate.Username) == "" ||
		strings.TrimSpace(candidate.Password) == "" ||
		isPlaceholder(candidate.Username) ||
		isPlaceholder(candidate.Password) {
		return credential{}, false
	}

	return candidate, true
}

func validHTTPURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "http") ||
		strings.EqualFold(parsed.Scheme, "https")
}

func isPlaceholder(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)

	switch lower {
	case "redacted", "[redacted]", "<redacted>":
		return true
	}

	if strings.HasPrefix(trimmed, "${") && strings.HasSuffix(trimmed, "}") ||
		strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") ||
		strings.HasPrefix(trimmed, "%") && strings.HasSuffix(trimmed, "%") {
		return true
	}

	for _, character := range trimmed {
		switch character {
		case '*', 'x', 'X', '•':
		default:
			return false
		}
	}
	return trimmed != ""
}

func redact(candidate credential) string {
	username := candidate.Username
	if candidate.Domain != "" {
		username = candidate.Domain + `\` + username
	}

	parsed, err := url.Parse(candidate.URL)
	if err != nil {
		return username
	}
	return username + "@" + parsed.Host
}
