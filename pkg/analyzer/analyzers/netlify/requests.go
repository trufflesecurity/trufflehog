package netlify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

var (
	apiEndpoints = map[ResourceType]string{
		CurrentUser:         "https://api.netlify.com/api/v1/user",
		Token:               "https://app.netlify.com/access-control/bb-api/api/v1/oauth/applications", // undocumented API - return personal tokens with metadata
		Site:                "https://api.netlify.com/api/v1/sites",
		SiteFile:            "https://api.netlify.com/api/v1/sites/%s/files",             // require site id
		SiteEnvVar:          "https://api.netlify.com/api/v1/sites/%s/env",               // require site id
		SiteSnippet:         "https://api.netlify.com/api/v1/sites/%s/snippets",          // require site id
		SiteDeploy:          "https://api.netlify.com/api/v1/sites/%s/deploys",           // require site id
		SiteDeployedBranch:  "https://api.netlify.com/api/v1/sites/%s/deployed-branches", // require site id
		SiteBuild:           "https://api.netlify.com/api/v1/sites/%s/builds",            // require site id
		SiteDevServer:       "https://api.netlify.com/api/v1/sites/%s/dev_servers",       // require site id
		SiteBuildHook:       "https://api.netlify.com/api/v1/sites/%s/build_hooks",       // require site id
		SiteDevServerHook:   "https://api.netlify.com/api/v1/sites/%s/dev_server_hooks",  // require site id
		SiteServiceInstance: "https://api.netlify.com/api/v1/sites/%s/service-instances", // require site id
		SiteFunction:        "https://api.netlify.com/api/v1/sites/%s/functions",         // require site id
		SiteForm:            "https://api.netlify.com/api/v1/sites/%s/forms",             // require site id
		SiteSubmission:      "https://api.netlify.com/api/v1/sites/%s/submissions",       // require site id
		SiteTrafficSplit:    "https://api.netlify.com/api/v1/sites/%s/traffic_splits",    // require site id
		DNSZone:             "https://api.netlify.com/api/v1/dns_zones",
		Service:             "https://api.netlify.com/api/v1/services",

		/*
			TODO APIs:
				- https://api.netlify.com/api/v1/sites/{site_id}/metadata (Just return key and values added as metadata for a site)
				- https://api.netlify.com/api/v1/sites/{site_id}/assets/{asset_id} (Require asset id - No API to list assets)
				- https://api.netlify.com/api/v1/deploy_keys (Have id and a public key in response only)
		*/
	}

	// metadata keys - should always start with resource name
	tokenPersonal      = "personal"
	tokenExpiresAt     = "expires_at"
	siteUrl            = "site_url"
	siteAdminUrl       = "site_admin_url"
	siteRepoUrl        = "site_repo_url"
	fileMimeType       = "site_mime_type"
	deployBuildID      = "deploy_build_id"
	deployState        = "deploy_state"
	deployUrl          = "deploy_url"
	deployedBranchSlug = "deployed_branch_slug"
	buildHookBranch    = "build_hook_branch"
	serviceInstanceUrl = "service_instance_url"
)

// makeNetlifyRequest send the API request to passed url with passed key as personal access token and return response body and status code
func makeNetlifyRequest(client *http.Client, endpoint, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add key in the header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return responseBodyByte, resp.StatusCode, nil
}

// captureResources try to capture all the resource that the key can access
func captureResources(client *http.Client, key string, secretInfo *SecretInfo) error {
	var (
		wg             sync.WaitGroup
		errAggWg       sync.WaitGroup
		aggregatedErrs = make([]error, 0)
		errChan        = make(chan error, 1)
	)

	errAggWg.Add(1)
	go func() {
		defer errAggWg.Done()
		for err := range errChan {
			aggregatedErrs = append(aggregatedErrs, err)
		}
	}()

	// helper to launch tasks concurrently.
	launchTask := func(task func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := task(); err != nil {
				errChan <- err
			}
		}()
	}

	// capture top level resources
	if err := captureSites(client, key, secretInfo); err != nil {
		return err
	}

	// capture all sub resources of all sites
	sites := secretInfo.listResourceByType(Site)
	for _, site := range sites {
		launchTask(func() error { return captureSiteFiles(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteEnvVar(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteSnippets(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteDeploys(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteDeployedBranches(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteBuilds(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteDevServers(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteBuildHooks(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteDevServerHooks(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteServiceInstances(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteFunctions(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteFormSubmissionSplitInfo(client, key, site, SiteForm, secretInfo) })
		launchTask(func() error { return captureSiteFormSubmissionSplitInfo(client, key, site, SiteSubmission, secretInfo) })
		launchTask(func() error {
			return captureSiteFormSubmissionSplitInfo(client, key, site, SiteTrafficSplit, secretInfo)
		})
	}

	launchTask(func() error { return captureDNSZones(client, key, secretInfo) })
	launchTask(func() error { return captureServices(client, key, secretInfo) })

	wg.Wait()
	close(errChan)
	errAggWg.Wait()

	if len(aggregatedErrs) > 0 {
		return errors.Join(aggregatedErrs...)
	}

	return nil
}

func captureUserInfo(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, apiEndpoints[CurrentUser], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var user User

		if err := json.Unmarshal(respBody, &user); err != nil {
			return err
		}

		secretInfo.UserInfo = user

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureTokens(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, apiEndpoints[Token], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var tokens []token

		if err := json.Unmarshal(respBody, &tokens); err != nil {
			return err
		}

		for _, token := range tokens {
			if token.ExpiresAt == "" {
				token.ExpiresAt = "never"
			}

			resource := NetlifyResource{
				ID:   token.ID,
				Name: token.Name,
				Type: Token.String(),
				Metadata: map[string]string{
					tokenExpiresAt: token.ExpiresAt,
					tokenPersonal:  strconv.FormatBool(token.Personal),
				},
			}

			secretInfo.Resources = append(secretInfo.Resources, resource)
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[Token])
	}
}

func captureSites(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, apiEndpoints[Site], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var sites []site

		if err := json.Unmarshal(respBody, &sites); err != nil {
			return err
		}

		for _, site := range sites {
			secretInfo.appendResource(NetlifyResource{
				ID:   site.SiteID,
				Name: site.Name,
				Type: Site.String(),
				Metadata: map[string]string{
					siteUrl:      site.Url,
					siteAdminUrl: site.AdminUrl,
					siteRepoUrl:  site.RepoUrl,
				},
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteFiles(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteFile], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var files []file

		if err := json.Unmarshal(respBody, &files); err != nil {
			return err
		}

		for _, file := range files {
			secretInfo.appendResource(NetlifyResource{
				ID:   site.ID + "/" + file.ID, // combine site id with file id to make it unique
				Name: file.Path,
				Type: SiteFile.String(),
				Metadata: map[string]string{
					fileMimeType: file.MimeType,
				},
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteEnvVar(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteEnvVar], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var envVariables []envVariable

		if err := json.Unmarshal(respBody, &envVariables); err != nil {
			return err
		}

		for _, envVar := range envVariables {
			// multiple values exist for each env variable, so we append separate resource for each value
			for _, value := range envVar.Values {
				secretInfo.appendResource(NetlifyResource{
					ID:   envVar.Key + "/" + value.ID,
					Name: envVar.Key + "/***" + value.Value[len(value.Value)-4:], // append last 4 characters of value with key to make it unique
					Type: SiteEnvVar.String(),
					Metadata: map[string]string{
						"value":  value.Value,
						"scopes": strings.Join(envVar.Scopes, ";"),
					},
					Parent: &site,
				})
			}
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteSnippets(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteSnippet], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var snippets []snippet

		if err := json.Unmarshal(respBody, &snippets); err != nil {
			return err
		}

		for _, snippet := range snippets {
			secretInfo.appendResource(NetlifyResource{
				ID:     snippet.ID,
				Name:   snippet.Title,
				Type:   SiteSnippet.String(),
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteDeploys(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteDeploy], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var deploys []deploy

		if err := json.Unmarshal(respBody, &deploys); err != nil {
			return err
		}

		for _, deploy := range deploys {
			secretInfo.appendResource(NetlifyResource{
				ID:   site.ID + "/deploy/" + deploy.ID,
				Name: deploy.Name,
				Type: SiteDeploy.String(),
				Metadata: map[string]string{
					deployBuildID: deploy.BuildID,
					deployState:   deploy.State,
					deployUrl:     deploy.Url,
				},
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteDeployedBranches(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteDeployedBranch], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var deployedBranches []deployedBranch

		if err := json.Unmarshal(respBody, &deployedBranches); err != nil {
			return err
		}

		for _, deployedBranch := range deployedBranches {
			secretInfo.appendResource(NetlifyResource{
				ID:   deployedBranch.ID,
				Name: deployedBranch.Name,
				Type: SiteDeployedBranch.String(),
				Metadata: map[string]string{
					deployedBranchSlug: deployedBranch.Slug,
				},
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteBuilds(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteBuild], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var builds []build

		if err := json.Unmarshal(respBody, &builds); err != nil {
			return err
		}

		for _, build := range builds {
			secretInfo.appendResource(NetlifyResource{
				ID:     build.ID,
				Name:   build.ID + "/state/" + build.DeployState, // no specific name
				Type:   SiteBuild.String(),
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteDevServers(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteDevServer], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var devServers []devServer

		if err := json.Unmarshal(respBody, &devServers); err != nil {
			return err
		}

		for _, devServer := range devServers {
			secretInfo.appendResource(NetlifyResource{
				ID:     devServer.ID,
				Name:   devServer.Title,
				Type:   SiteDevServer.String(),
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteBuildHooks(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteBuildHook], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var hooks []buildHook

		if err := json.Unmarshal(respBody, &hooks); err != nil {
			return err
		}

		for _, hook := range hooks {
			secretInfo.appendResource(NetlifyResource{
				ID:   hook.ID,
				Name: hook.Title,
				Type: SiteBuildHook.String(),
				Metadata: map[string]string{
					buildHookBranch: hook.Branch,
				},
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteDevServerHooks(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteDevServerHook], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var devServerHooks []buildHook

		if err := json.Unmarshal(respBody, &devServerHooks); err != nil {
			return err
		}

		for _, hook := range devServerHooks {
			secretInfo.appendResource(NetlifyResource{
				ID:   hook.ID,
				Name: hook.Title,
				Type: SiteDevServerHook.String(),
				Metadata: map[string]string{
					buildHookBranch: hook.Branch,
				},
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteServiceInstances(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteServiceInstance], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var serviceInstances []serviceInstance

		if err := json.Unmarshal(respBody, &serviceInstances); err != nil {
			return err
		}

		for _, instance := range serviceInstances {
			secretInfo.appendResource(NetlifyResource{
				ID:   instance.ID,
				Name: instance.ServiceName + "/instance/" + instance.ID, // no specific name
				Type: SiteServiceInstance.String(),
				Metadata: map[string]string{
					serviceInstanceUrl: instance.Url,
				},
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteFunctions(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteFunction], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var data function

		if err := json.Unmarshal(respBody, &data); err != nil {
			return err
		}

		secretInfo.appendResource(NetlifyResource{
			ID:     data.ID,
			Name:   "function/" + data.ID + "/provider/" + data.Provider, // no specific name
			Type:   SiteFunction.String(),
			Parent: &site,
		})

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteFormSubmissionSplitInfo(client *http.Client, key string, site NetlifyResource, resType ResourceType, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[resType], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var formSubSplitInfos []formSubmissionSplitInfo

		if err := json.Unmarshal(respBody, &formSubSplitInfos); err != nil {
			return err
		}

		for _, info := range formSubSplitInfos {
			secretInfo.appendResource(NetlifyResource{
				ID:     info.ID,
				Name:   info.Name, // no specific name
				Type:   resType.String(),
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureDNSZones(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, apiEndpoints[DNSZone], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var dnsZones []dnsZone

		if err := json.Unmarshal(respBody, &dnsZones); err != nil {
			return err
		}

		for _, dnsZone := range dnsZones {
			secretInfo.appendResource(NetlifyResource{
				ID:   dnsZone.ID,
				Name: dnsZone.Name,
				Type: DNSZone.String(),
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureServices(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, apiEndpoints[Service], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var services []service

		if err := json.Unmarshal(respBody, &services); err != nil {
			return err
		}

		for _, service := range services {
			secretInfo.appendResource(NetlifyResource{
				ID:   service.ID,
				Name: service.Name,
				Type: Service.String(),
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}
