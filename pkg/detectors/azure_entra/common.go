package azure_entra

import (
	"fmt"
	"io"
	"net/http"
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
		`(?i)(?:(?:login\.microsoftonline\.com/|(?:login|sts)\.windows\.net/|(?:t[ae]n[ae]nt(?:[ ._-]?id)?|\btid)(?:.|\s){0,60}?)(%s)|https?://(%s)|X-AnchorMailbox(?:.|\s){0,60}?@(%s))`,
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
	uniqueMatches := make(map[string]struct{})

	for _, match := range tenantIdPat.FindAllStringSubmatch(data, -1) {
		var m string
		if match[1] != "" {
			m = strings.ToLower(match[1])
		} else if match[2] != "" {
			m = strings.ToLower(match[2])
		} else if match[3] != "" {
			m = strings.ToLower(match[3])
		}
		if _, ok := detectors.UuidFalsePositives[detectors.FalsePositive(m)]; ok {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}
	for _, match := range tenantOnMicrosoftPat.FindAllStringSubmatch(data, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}
	return uniqueMatches
}

// FindClientIdMatches returns a list of potential client UUIDs in the provided |data|.
func FindClientIdMatches(data string) map[string]struct{} {
	uniqueMatches := make(map[string]struct{})
	for _, match := range clientIdPat.FindAllStringSubmatch(data, -1) {
		m := strings.ToLower(match[1])
		if _, ok := detectors.UuidFalsePositives[detectors.FalsePositive(m)]; ok {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}
	return uniqueMatches
}

var (
	tenantCache = simple.NewCache[bool]()
	tenantGroup singleflight.Group
)

// TenantExists returns whether the tenant exists according to Microsoft's well-known OpenID endpoint.
func TenantExists(ctx context.Context, client *http.Client, tenant string) bool {
	// Use cached value where possible.
	if tenantExists, isCached := tenantCache.Get(tenant); isCached {
		return tenantExists
	}

	// https://www.codingexplorations.com/blog/understanding-singleflight-in-golang-a-solution-for-eliminating-redundant-work
	tenantExists, _, _ := tenantGroup.Do(tenant, func() (interface{}, error) {
		result := queryTenant(ctx, client, tenant)
		tenantCache.Set(tenant, result)
		return result, nil
	})

	return tenantExists.(bool)
}

func queryTenant(ctx context.Context, client *http.Client, tenant string) bool {
	logger := ctx.Logger().WithName("azure").WithValues("tenant", tenant)

	tenantUrl := fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", tenant)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tenantUrl, nil)
	if err != nil {
		return false
	}

	res, err := client.Do(req)
	if err != nil {
		logger.Error(err, "Failed to check if tenant exists")
		return false
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusBadRequest:
		logger.V(4).Info("Tenant does not exist.")
		return false
	default:
		bodyBytes, _ := io.ReadAll(res.Body)
		logger.Error(nil, "WARNING: Unexpected response when checking if tenant exists", "status_code", res.StatusCode, "body", string(bodyBytes))
		return false
	}
}
