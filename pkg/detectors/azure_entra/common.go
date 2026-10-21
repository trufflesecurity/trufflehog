package azure_entra

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/sync/singleflight"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

const uuidStr = `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`

var (
	// Tenants can be identified with a UUID or an `*.onmicrosoft.com` domain.
	//
	// See:
	// https://learn.microsoft.com/en-us/partner-center/account-settings/find-ids-and-domain-names#find-the-microsoft-azure-ad-tenant-id-and-primary-domain-name
	// https://learn.microsoft.com/en-us/microsoft-365/admin/setup/domains-faq?view=o365-worldwide#why-do-i-have-an--onmicrosoft-com--domain
	tenantIdPat = regexp.MustCompile(fmt.Sprintf(
		//language=regexp
		`(?i)(?:(?:login\.microsoftonline\.com/|(?:login|sts)\.windows\.net/|(?:t[ae]n[ae]nt(?:[ ._-]?id)?|\btid)(?:.|\s){0,60}?)(%s)|https?://(%s)|X-AnchorMailbox(?:.|\s){0,60}?@(%s)|/(%s)/(?:oauth2/v2\.0|B2C_1\w+|common|discovery|federationmetadata|kerberos|login|openid/|reprocess|resume|saml2|token|uxlogout|v2\.0|wsfed))`,
		uuidStr,
		uuidStr,
		uuidStr,
		uuidStr,
	))
	tenantOnMicrosoftPat = regexp.MustCompile(`([\w-]+\.onmicrosoft\.com)`)

	clientIdPat = regexp.MustCompile(fmt.Sprintf(
		`(?i)(?:(?:app(?:lication)?|client)(?:[ ._-]?id)?|username| -u)(?:.|\s){0,45}?(%s)`, uuidStr))
)

// FindTenantIdMatches returns a list of potential tenant IDs in the provided |data|.
func FindTenantIdMatches(data string) map[string]struct{} {
	return offsetsToSet(FindTenantIdOffsets(data))
}

// FindTenantIdOffsets returns potential tenant IDs in |data|, mapped to the byte offsets where each was found.
func FindTenantIdOffsets(data string) map[string][]int {
	matches := make(map[string][]int)

	for _, idx := range tenantIdPat.FindAllStringSubmatchIndex(data, -1) {
		// The pattern has four alternative capture groups; use the one that matched.
		for group := 1; group <= 4; group++ {
			start, end := idx[2*group], idx[2*group+1]
			if start < 0 {
				continue
			}
			m := strings.ToLower(data[start:end])
			if isLikelyId(m) {
				matches[m] = append(matches[m], start)
			}
			break
		}
	}
	for _, idx := range tenantOnMicrosoftPat.FindAllStringSubmatchIndex(data, -1) {
		m := data[idx[2]:idx[3]]
		matches[m] = append(matches[m], idx[2])
	}
	return matches
}

// FindClientIdMatches returns a list of potential client UUIDs in the provided |data|.
func FindClientIdMatches(data string) map[string]struct{} {
	return offsetsToSet(FindClientIdOffsets(data))
}

// FindClientIdOffsets returns potential client UUIDs in |data|, mapped to the byte offsets where each was found.
func FindClientIdOffsets(data string) map[string][]int {
	matches := make(map[string][]int)
	for _, idx := range clientIdPat.FindAllStringSubmatchIndex(data, -1) {
		m := strings.ToLower(data[idx[2]:idx[3]])
		if isLikelyId(m) {
			matches[m] = append(matches[m], idx[2])
		}
	}
	return matches
}

// NearestFirst returns the keys of |candidates| ordered by their distance to |pos|.
// A candidate's distance is that of its closest occurrence. Ties are broken by value so the order is stable.
func NearestFirst(candidates map[string][]int, pos int) []string {
	distances := make(map[string]int, len(candidates))
	ordered := make([]string, 0, len(candidates))
	for value, offsets := range candidates {
		closest := -1
		for _, offset := range offsets {
			d := offset - pos
			if d < 0 {
				d = -d
			}
			if closest < 0 || d < closest {
				closest = d
			}
		}
		distances[value] = closest
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if distances[ordered[i]] != distances[ordered[j]] {
			return distances[ordered[i]] < distances[ordered[j]]
		}
		return ordered[i] < ordered[j]
	})
	return ordered
}

// isLikelyId filters out well-known placeholder UUIDs and low-entropy values.
func isLikelyId(m string) bool {
	if _, ok := detectors.UuidFalsePositives[detectors.FalsePositive(m)]; ok {
		return false
	}
	return detectors.StringShannonEntropy(m) >= 3
}

func offsetsToSet(offsets map[string][]int) map[string]struct{} {
	set := make(map[string]struct{}, len(offsets))
	for value := range offsets {
		set[value] = struct{}{}
	}
	return set
}

var (
	tenantCache = simple.NewCache[bool]()
	tenantGroup singleflight.Group
)

// TenantExists returns whether the tenant exists according to Microsoft's well-known OpenID endpoint.
// A non-nil error means the answer is unknown (e.g., a network failure); it is not cached.
func TenantExists(ctx context.Context, client *http.Client, tenant string) (bool, error) {
	// Use cached value where possible.
	if tenantExists, isCached := tenantCache.Get(tenant); isCached {
		return tenantExists, nil
	}

	// https://www.codingexplorations.com/blog/understanding-singleflight-in-golang-a-solution-for-eliminating-redundant-work
	tenantExists, err, _ := tenantGroup.Do(tenant, func() (interface{}, error) {
		result, err := queryTenant(ctx, client, tenant)
		// Only remember definite answers, so a transient failure doesn't stick.
		if err == nil {
			tenantCache.Set(tenant, result)
		}
		return result, err
	})
	if err != nil {
		return false, err
	}

	return tenantExists.(bool), nil
}

func queryTenant(ctx context.Context, client *http.Client, tenant string) (bool, error) {
	logger := ctx.Logger().WithName("azure").WithValues("tenant", tenant)

	tenantUrl := fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", tenant)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tenantUrl, nil)
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		logger.Error(err, "Failed to check if tenant exists")
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest:
		logger.V(4).Info("Tenant does not exist.")
		return false, nil
	default:
		bodyBytes, _ := io.ReadAll(res.Body)
		logger.Error(nil, "WARNING: Unexpected response when checking if tenant exists", "status_code", res.StatusCode, "body", string(bodyBytes))
		return false, fmt.Errorf("unexpected status %d checking tenant", res.StatusCode)
	}
}
