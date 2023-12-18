package npm

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNpm_KnownRegistryPat(t *testing.T) {
	cases := map[registryType]map[string][]string{
		npm: {
			"//registry.npmjs.org/":       {"//", "registry.npmjs.org"},
			"https://registry.npmjs.org/": {"https://", "registry.npmjs.org"},
			`  resolved "https://registry.yarnpkg.com/abstract-logging/-/abstract-logging-2.0.1.tgz#6b0c371df212db7129b57d2e7fcf282b8bf1c839"`: {"https://", "registry.yarnpkg.com"},
		},
		artifactoryHosted: {
			"https://artifactory.prd.cds.internal.unity3d.com/artifactory/api/npm/upm-npm/": {"https://", "artifactory.prd.cds.internal.unity3d.com/artifactory/api/npm/upm-npm"},
			"registry=http://10.85.59.116/artifactory/v1.0/artifacts/npm/":                  {"http://", "10.85.59.116/artifactory/v1.0/artifacts/npm"},
		},
		artifactoryCloud: {
			"//voomp.jfrog.io/artifactory/api/npm/vk-common-bk/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d":  {"//", "voomp.jfrog.io/artifactory/api/npm/vk-common-bk"},
			"//geckorobotics.jfrog.io/geckorobotics/api/npm/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d": {"//", "geckorobotics.jfrog.io/geckorobotics/api/npm/npm"},
		},
		nexusRepo2: {
			"http://nexus.zenoss.eng:8081/nexus/content/repositories/npm/":     {"http://", "nexus.zenoss.eng:8081/nexus/content/repositories/npm"},
			"http://nexus.pas-mini.io/nexus/content/repositories/npm-private/": {"http://", "nexus.pas-mini.io/nexus/content/repositories/npm-private"},
		},
		nexusRepo3: {
			"registry=http://34.125.69.241/repository/npm-group/":                                    {"http://", "34.125.69.241/repository/npm-group"},
			"https://repo.huaweicloud.com/repository/npm/":                                           {"https://", "repo.huaweicloud.com/repository/npm"},
			"http://artifacts.lan.tribe29.com:8081/repository/npm-proxy/@babel/":                     {"http://", "artifacts.lan.tribe29.com:8081/repository/npm-proxy"},
			"http://10.10.69.203:8081/repository/npm-group/":                                         {"http://", "10.10.69.203:8081/repository/npm-group"},
			"//nexus.public.prd.golf-prod.js-devops.co.uk/repository/luna/":                          {"//", "nexus.public.prd.golf-prod.js-devops.co.uk/repository/luna"},
			"//ec2-18-222-132-112.us-east-2.compute.amazonaws.com:8081/repository/postboard-server/": {"//", "ec2-18-222-132-112.us-east-2.compute.amazonaws.com:8081/repository/postboard-server"},
			`- name: NPM_PUBLISH_URL
  description: "Maven repository url to where jenkins will upload releases artifacts"
  required: true
  value: "http://nexus3.my-company.tk:8081/repository/npm-releases/"
- name: NPM_PUBLISH_TOKEN
  description: "Npm user used when upload artifacts"
  required: true
  value: "NpmToken.b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb"`: {"http://", "nexus3.my-company.tk:8081/repository/npm-releases"},
			`<figure class="highlight shell"><table><tr><td class="gutter"><pre><span class="line">1</span><br><span class="line">2</span><br><span class="line">3</span><br></pre></td><td class="code"><pre><span class="line">[root@nexus3 ~]# cat ~/.npmrc</span><br><span class="line">registry=http://registry.blog.co/repository/npm-group/</span><br><span class="line">//registry.blog.co/repository/npm-group/:_authToken=NpmToken.72b83be3-4b24-3dd1-850f-056cd78bb513</span><br></pre></td></tr></table></figure>`: {"http://", "registry.blog.co/repository/npm-group"},
		},
		gitlab: {
			`"https://gitlab.matrix.org/api/v4/projects/27/packages/npm/@matrix-org/olm/-/@matrix-org/olm-3.2.3.tgz",`: {"https://", "gitlab.matrix.org/api/v4/projects/27/packages/npm"},
			"https://gitlab.com/api/v4/groups/123456/-/packages/npm/":                                                  {"https://", "gitlab.com/api/v4/groups/123456/-/packages/npm"}, // couldn't find a real example of this
		},
		github: {
			"https://npm.pkg.github.com/":        {"https://", "npm.pkg.github.com"},
			"https://npm.pkg.github.com/company": {"https://", "npm.pkg.github.com"},
		},
		azure: {
			"//pkgs.dev.azure.com/company/_packaging/feed/npm/":                                                 {"//", "pkgs.dev.azure.com/company/_packaging/feed/npm"},
			"https://pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry/":                          {"https://", "pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry"},
			"https://pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry":                           {"https://", "pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry"},
			"//pkgs.dev.azure.com/company/b675ba30-3f64-43c8-b35d-79c162dc3fd7/_packaging/feed/npm/":            {"//", "pkgs.dev.azure.com/company/b675ba30-3f64-43c8-b35d-79c162dc3fd7/_packaging/feed/npm"},
			"//fso-to.pkgs.visualstudio.com/7bc545d8-bf8c-477e-bb91-17a982c30c2e/_packaging/feed/npm/registry/": {"//", "fso-to.pkgs.visualstudio.com/7bc545d8-bf8c-477e-bb91-17a982c30c2e/_packaging/feed/npm/registry"},
			"//company.pkgs.visualstudio.com/project/_packaging/feed/npm/registry/":                             {"//", "company.pkgs.visualstudio.com/project/_packaging/feed/npm/registry"},
			"//company.pkgs.visualstudio.com/_packaging/feed/npm/registry/:username=bart":                       {"//", "company.pkgs.visualstudio.com/_packaging/feed/npm/registry"},
		},
		jetbrains: {
			"//npm.pkg.jetbrains.space/multiplier/p/multiplier/npm/":                        {"//", "npm.pkg.jetbrains.space/multiplier/p/multiplier/npm"},
			"https://npm.pkg.jetbrains.space/nridwan/p/main/npmempty/":                      {"https://", "npm.pkg.jetbrains.space/nridwan/p/main/npmempty"},
			"https://npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev/": {"https://", "npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev"},
		},
		googleArtifactRegistry: {
			"https://us-west1-npm.pkg.dev/company/project":                                      {"https://", "us-west1-npm.pkg.dev/company/project"},
			"https://npm.pkg.dev/company/project":                                               {"https://", "npm.pkg.dev/company/project"},
			"//europe-west4-npm.pkg.dev/foleon-staging/foleon-libs/:username=oauth2accesstoken": {"//", "europe-west4-npm.pkg.dev/foleon-staging/foleon-libs"},
		},
		gemfury: {
			"//npm.fury.io/dependabot/": {"//", "npm.fury.io/dependabot"},
		},
	}
	for group, inputs := range cases {
		t.Run(group.String(), func(t *testing.T) {
			for input, expected := range inputs {
				matches := knownRegistryPat.FindStringSubmatch(input)
				if len(matches) == 0 {
					t.Errorf("no result for %s", input)
					return
				}

				index, uri := firstNonEmptyMatch(matches, 2)
				rType := registryType(index - 1)
				if rType != group {
					t.Errorf("expected type %s, got %s (%s)", group.String(), rType.String(), input)
				}
				if matches[1] != expected[0] {
					t.Errorf("expected prefix %s, got %s (%s)", expected[0], matches[1], input)
				}
				if uri != expected[1] {
					t.Errorf("expected uri %s, got %s (%s)", expected[1], uri, input)
				}
			}
		})
	}
}

func TestNpm_GenericRegistryPat(t *testing.T) {
	// TODO: Support localhost and other names?
	cases := map[string]string{
		// .npmrc
		"registry = https://npm.company.de:4873/":                                               "https://npm.company.de:4873",
		"registry=https://registry.npm.taobao.org/":                                             "https://registry.npm.taobao.org",
		`"registry" "https://registry.npmmirror.com/"`:                                          "https://registry.npmmirror.com",
		`@company:registry="https://npm.company.io"`:                                            "https://npm.company.io",
		"@marketwall:registry=http://10.0.0.13:4873":                                            "http://10.0.0.13:4873",
		`"@fortawesome:registry" "https://npm.fontawesome.com/"`:                                "https://npm.fontawesome.com",
		"@example=https://api.bintray.example/npm/mycompany/myregistry":                         "https://api.bintray.example/npm/mycompany/myregistry",
		`"@example" "https://api.bintray.example/npm/mycompany/myregistry"`:                     "https://api.bintray.example/npm/mycompany/myregistry",
		"//npm.company.com/:_authToken='fake123'":                                               "//npm.company.com",
		"//registry-node.company.com/org/1123600651823311/registry/supermap/:_password=123fake": "//registry-node.company.com/org/1123600651823311/registry/supermap",
		`"//npm.fontawesome.com/:_authToken" "XXXXXXX-my-token"`:                                "//npm.fontawesome.com",
		`registry=http://55825a54e4454.registry.net:8443/`:                                      "http://55825a54e4454.registry.net:8443",
		// yarnrc.yml
		`npmScopes:
  "my-company":
    npmAlwaysAuth: true
    npmAuthToken: xxx-xxx
    npmRegistryServer: "https://repo.company.org/npm"`: "https://repo.company.org/npm",
		`  await fixture.exec("yarn config set npmRegistryServer http://npm.corp.xyz:8080");`:                          "http://npm.corp.xyz:8080",
		`yarn config set npmScopes --json '{ "storybook": { "npmRegistryServer": "http://repo.company.org:6001/" } }'`: "http://repo.company.org:6001",
		`yarn config set npmScopes.my-org.npmRegistryServer "https://repo.company.org/npm/nested"`:                     "https://repo.company.org/npm/nested",
		`  npmScopes:
    company:
      npmRegistryServer: '${METAMASK_NPM_REGISTRY:-https://your.company.com/private/registry}'`: "https://your.company.com/private/registry",
		// upmconfig.toml
		`[npmAuth."https://api.bintray.com/npm/joe-company/my-registry"]`:                    "https://api.bintray.com/npm/joe-company/my-registry",
		`echo "[npmAuth.'https://your.company.com/private/registry/']" >> ~/.upmconfig.toml`: "https://your.company.com/private/registry",
	}
	for input, expected := range cases {
		if knownRegistryPat.MatchString(input) {
			t.Errorf("matches |knownRegistryPat|: %s", input)
			continue
		}

		matches := genericRegistryPat.FindStringSubmatch(input)
		if len(matches) == 0 {
			t.Errorf("received no matches for '%s'\n", input)
			continue
		}

		_, match := firstNonEmptyMatch(matches, 1)
		if match != expected {
			t.Errorf("expected '%s', got '%s'\n\t(%s)", expected, match, input)
		}
	}
}

func TestNpm_FindTokenRegistry(t *testing.T) {
	cases := map[string]struct {
		data     string
		token    string
		expected *registryInfo
	}{
		".npmrc / _auth / top-level / no registry": {
			data:     "_auth = \"cGFzc3dvcmQ=\"\nemail = john.doe@example.com",
			token:    "cGFzc3dvcmQ=",
			expected: nil,
		},
		// TODO: Associate top-level auth with top-level registry.
		//".npmrc / _auth / top-level / registry": {
		//	input: "_auth = \"cGFzc3dvcmQ=\"\nalways-auth = true\nregistry=https://nexus.company.com/repository/npm-group/",
		//	token: "cGFzc3dvcmQ=",
		//	expected: &registryInfo{
		//		RegistryType: nexusRepo3,
		//		Scheme:       httpsScheme,
		//		Uri:          "nexus.company.com/repository/npm-group",
		//	},
		//},
		".npmrc / _auth / scoped / registry": {
			data:  "\"//artifactory.company.com/artifactory/api/npm/npm/:_auth\"=cGFzc3dvcmQ=\n",
			token: "cGFzc3dvcmQ=",
			expected: &registryInfo{
				RegistryType: artifactoryHosted,
				Scheme:       unknown,
				Uri:          "artifactory.company.com/artifactory/api/npm/npm",
			},
		},

		".npmrc / _authToken / registry": {
			data:  `"//artifactory.company.com/artifactory/api/npm/npm/:_authToken" "=cGFzc3dvcmQ="`,
			token: "cGFzc3dvcmQ=",
			expected: &registryInfo{
				RegistryType: artifactoryHosted,
				Scheme:       unknown,
				Uri:          "artifactory.company.com/artifactory/api/npm/npm",
			},
		},
		"cli / _authToken / registry": {
			data:  "npm config set @company:registry=https://npm.pkg.github.com/\nnpm config set //npm.pkg.github.com/:_authToken=ghp_sS3gaQUHaXSdwojeksTlaIAgJ7jWsn4D7gPO\n",
			token: "ghp_sS3gaQUHaXSdwojeksTlaIAgJ7jWsn4D7gPO",
			expected: &registryInfo{
				RegistryType: github,
				Scheme:       isHttps,
				Uri:          "npm.pkg.github.com",
			},
		},
		"cli / _authToken / multiple registries": {
			data:  "npm config set @other:registry=https://npm.pkg.github.com/\nnpm config set //npm.pkg.github.com/:_authToken=ghp_sS3gaQUHaXSdwojeksTlaIAgJ7jWsn4D7gPO\nnpm config set \"@fortawesome:registry\" https://npm.fontawesome.com/\nnpm config set \"//npm.fontawesome.com/:_authToken\" cGFzc3dvcmQ=",
			token: "cGFzc3dvcmQ=",
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "npm.fontawesome.com",
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			actual := findTokenRegistry(test.data, test.token)

			ignoreOpts := cmpopts.IgnoreFields(registryInfo{})
			if diff := cmp.Diff(test.expected, actual, ignoreOpts); diff != "" {
				t.Errorf("diff: (-expected +actual)\n%s", diff)
			}
		})
	}
}

type registryTestCase struct {
	input    string
	expected *registryInfo
}

func TestNpm_FindAllRegistryURLs_Known(t *testing.T) {
	cases := map[string]registryTestCase{
		"npm - default": {
			input: `NpmToken.35ea93c4-8c57-4a7c-8526-115b9eeeab8a`,
			expected: &registryInfo{
				RegistryType: npm,
				Scheme:       isHttps,
				Uri:          "registry.npmjs.org",
			},
		},
		"npm": {
			input: "//registry.npmjs.org/:_authToken=cGFzc3dvcmQ=",
			expected: &registryInfo{
				RegistryType: npm,
				Scheme:       isHttps,
				Uri:          "registry.npmjs.org",
			},
		},
		"artifactoryHosted": {
			input: `//repo.company.com/artifactory/api/npm/npm-repo/:_password=cGFzc3dvcmQ=`,
			expected: &registryInfo{
				RegistryType: artifactoryHosted,
				Uri:          "repo.company.com/artifactory/api/npm/npm-repo",
			},
		},
		"artifactoryCloud": {
			input: `//company.jfrog.io/company/api/npm/npm/:_authToken=cGFzc3dvcmQ=`,
			expected: &registryInfo{
				RegistryType: artifactoryCloud,
				Scheme:       isHttps,
				Uri:          "company.jfrog.io/company/api/npm/npm",
			},
		},
		"nexusRepo2 - repository": {
			input: `//nexus.company.org:8081/nexus/content/repositories/npm`,
			expected: &registryInfo{
				RegistryType: nexusRepo2,
				Uri:          "nexus.company.org:8081/nexus/content/repositories/npm",
			},
		},
		"nexusRepo2 - group": {
			input: `//nexus.company.org:8081/nexus/content/groups/npm`,
			expected: &registryInfo{
				RegistryType: nexusRepo2,
				Uri:          "nexus.company.org:8081/nexus/content/groups/npm",
			},
		},
		"nexusRepo3": {
			input: `//nexus.company.com/repository/npm-proxy`,
			expected: &registryInfo{
				RegistryType: nexusRepo3,
				Uri:          "nexus.company.com/repository/npm-proxy",
			},
		},
		"gitlab - project": {
			input: `//gitlab.matrix.org/api/v4/projects/27/packages/npm/`,
			expected: &registryInfo{
				RegistryType: gitlab,
				Uri:          "gitlab.matrix.org/api/v4/projects/27/packages/npm",
			},
		},
		"gitlab - group": {
			input: `//gitlab.com/api/v4/groups/1234/-/packages/npm/`,
			expected: &registryInfo{
				RegistryType: gitlab,
				Uri:          "gitlab.com/api/v4/groups/1234/-/packages/npm",
			},
		},
		// This is apparently a thing? No idea, found it in the wild though.
		"gitlab - top-level": {
			input: `"//code.company.com/api/v4/packages/npm/:_authToken" "ZENNP-123456789"`,
			expected: &registryInfo{
				RegistryType: gitlab,
				Uri:          "code.company.com/api/v4/packages/npm",
			},
		},
		"github": {
			input: `//npm.pkg.github.com/`,
			expected: &registryInfo{
				RegistryType: github,
				Scheme:       isHttps,
				Uri:          "npm.pkg.github.com",
			},
		},
		"azure - org": {
			input: `//pkgs.dev.azure.com/company/_packaging/feed/npm/registry/`,
			expected: &registryInfo{
				RegistryType: azure,
				Scheme:       isHttps,
				Uri:          "pkgs.dev.azure.com/company/_packaging/feed/npm/registry",
			},
		},
		"azure - repo": {
			input: `//pkgs.dev.azure.com/company/project/_packaging/feed/npm/`,
			expected: &registryInfo{
				RegistryType: azure,
				Scheme:       isHttps,
				Uri:          "pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry",
			},
		},
		"azure - visualstudio": {
			input: `//company.pkgs.visualstudio.com/05337347-30ac-46d4-b46f-5f5cb80c6818/_packaging/feed/npm/registry/`,
			expected: &registryInfo{
				RegistryType: azure,
				Scheme:       isHttps,
				Uri:          "company.pkgs.visualstudio.com/05337347-30ac-46d4-b46f-5f5cb80c6818/_packaging/feed/npm/registry",
			},
		},
		"google artifact registry": {
			input: `@rbl:registry=https://us-central1-npm.pkg.dev/company/project/
//us-central1-npm.pkg.dev/company/project/:_authToken="ya29.A0ARrdaM9VpQcc5egcSN7zzEGQLzvz5jZiXEkIDmnsV2RW3KBbhbq8qkRHMUcC6gxknE9LuDW3mt4Dz3teWYXfI-4WGr6_mTQqj60BhAg4sPA7wov7PM-E3QonNwTN9De41ARPJUyvfc8Mi2GVoYzle3MJ_8KNYo4"
//us-central1-npm.pkg.dev/company/project/:always-auth=true`,
			expected: &registryInfo{
				RegistryType: googleArtifactRegistry,
				Scheme:       isHttps,
				Uri:          "us-central1-npm.pkg.dev/company/project",
			},
		},
		"jetbrains": {
			input: `//npm.pkg.jetbrains.space/company/p/project/repo/`,
			expected: &registryInfo{
				RegistryType: jetbrains,
				Scheme:       isHttps,
				Uri:          "npm.pkg.jetbrains.space/company/p/project/repo",
			},
		},
		"gemfury": {
			input: `//npm.fury.io/user/`,
			expected: &registryInfo{
				RegistryType: gemfury,
				Scheme:       isHttps,
				Uri:          "npm.fury.io/user",
			},
		},
	}

	for name, tCase := range cases {
		expected := *tCase.expected

		schemes := [...]scheme{unknown, isHttp, isHttps}
		for _, scheme := range schemes {
			var (
				expected = expected
				uri      = expected.Uri
				input    string
			)

			if expected.Scheme == unknown {
				expected.Scheme = scheme
			}

			if scheme == unknown {
				input = tCase.input
			} else if scheme == isHttp {
				input = fmt.Sprintf("registry=http://%s/\n%s", uri, tCase.input)
			} else {
				input = fmt.Sprintf("registry=https://%s/\n%s", uri, tCase.input)
			}

			t.Run(fmt.Sprintf("%s - %s", name, scheme.String()), func(t *testing.T) {
				urls := findAllRegistryURLs(input)
				if len(urls) != 1 {
					t.Errorf("expected 1 result, got %d", len(urls))
					return
				}

				var actual registryInfo
				for _, i := range urls {
					actual = *i
				}

				if diff := cmp.Diff(expected, actual); diff != "" {
					t.Errorf("diff: (-expected +actual)\n%s", diff)
				}
			})
		}
	}
}

func TestNpm_FindAllRegistryURLs_Unknown(t *testing.T) {
	cases := map[string]registryTestCase{
		"nothing - default": {
			input:    `NpmToken.35ea93c4-8c57-4a7c-8526-115b9eeeab8a`,
			expected: defaultRegistryInfo,
		},
		"package.json - publishConfig": {
			input: `"\"publishConfig\": {\n    \"registry\": \"http://repository.dsv.myhost/npmjs\"\n  },`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttp,
				Uri:          "repository.dsv.myhost/npmjs",
			},
		},
		"cli - publish registry flag": {
			input: `//npm publish --registry http://ec2-18-223-132-112.us-east-2.compute.amazonaws.com:8081/npm/`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttp,
				Uri:          "ec2-18-223-132-112.us-east-2.compute.amazonaws.com:8081/npm",
			},
		},
		"cli - publish scoped registry flag": {
			input: `//npm publish --@myscope:registry=http://internal.company.com/packages/npmjs-registry/`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttp,
				Uri:          "internal.company.com/packages/npmjs-registry",
			},
		},
		"cli - config registry": {
			input: `npm config set registry "https://npm.company.com/"`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "npm.company.com",
			},
		},
		"cli - config scope registry": {
			input: `npm config set "@company:registry" "https://npm.company.com/"`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "npm.company.com",
			},
		},
		"cli - config authToken": {
			input: `npm config set "//npm.company.com/:_authToken" token123`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       unknown,
				Uri:          "npm.company.com",
			},
		},
		".npmrc - registry": {
			input: `"registry=https://npm.company.com/`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "npm.company.com",
			},
		},
		".npmrc - scope registry": {
			input: `@company:registry = https://repo.company.com:8443/`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "repo.company.com:8443",
			},
		},
		".npmrc - scope registry, no equals": {
			input: `"@company:registry" "https://artifacts.company.com/npm/"`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "artifacts.company.com/npm",
			},
		},
		".npmrc - scope": {
			input: `@company = "https://repo.company.com/"`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "repo.company.com",
			},
		},
		".npmrc - _auth": {
			input: `"//npm.company.com/:_auth" = "cGFzc3dvcmQ="`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       unknown,
				Uri:          "npm.company.com",
			},
		},
		".npmrc - _auth with https context": {
			input: `"//npm.company.com/:_auth" = "cGFzc3dvcmQ="
registry=https://npm.company.com/`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "npm.company.com",
			},
		},
		".npmrc - _auth with http context": {
			input: `"//npm.company.com/:_auth" = "cGFzc3dvcmQ="
registry=http://npm.company.com/`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttp,
				Uri:          "npm.company.com",
			},
		},
		".npmrc - _password": {
			input: `//npm.company.com/:_password=cGFzc3dvcmQ=`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       unknown,
				Uri:          "npm.company.com",
			},
		},
		// https://docs.unity3d.com/Manual/upm-config-scoped.html
		".upmconfig.toml": {
			input: `[npmAuth."https://api.bintray.example/npm/mycompany/myregistry"]`,
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "api.bintray.example/npm/mycompany/myregistry",
			},
		},
		// TODO: https://github.com/renovatebot/renovate/blob/075a96c00aa53ede32576e924fe81b040789fc14/docs/usage/getting-started/private-packages.md
		//"renovatebot": {
		//	input: `      matchHost: 'https://packages.my-company.com/myregistry/',`,
		//	expected: &registryInfo{
		//		RegistryType: other,
		//		Scheme:       isHttps,
		//		Uri:          "packages.my-company.com/myregistry",
		//	},
		//},
	}

	for name, tCase := range cases {
		t.Run(name, func(t *testing.T) {
			urls := findAllRegistryURLs(tCase.input)
			if len(urls) != 1 {
				t.Errorf("expected 1 result for %s, got %d (%v)", tCase.input, len(urls), urls)
			}

			var actualInfo *registryInfo
			for _, i := range urls {
				actualInfo = i
			}

			if diff := cmp.Diff(tCase.expected, actualInfo); diff != "" {
				t.Errorf("diff: (-expected +actual)\n%s", diff)
			}
		})
	}
}

func TestNpm_ParseKnownRegistryUri(t *testing.T) {
	cases := map[registryType]struct {
		data     string
		uri      string
		expected *registryInfo
	}{
		other: {
			data:     `//npm.fontawesome.com/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:      "npm.fontawesome.com",
			expected: nil,
		},
		npm: {
			data: `//registry.npmjs.org/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//registry.npmjs.org",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "registry.npmjs.org",
			},
		},
		artifactoryCloud: {
			data: `//company.jfrog.io/company/api/npm/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//company.jfrog.io/company/api/npm/npm",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "company.jfrog.io/company/api/npm/npm",
			},
		},
		artifactoryHosted: {
			data: "registry=http://artifactory.internal-dev.company.net/artifactory/api/npm/npm/\n//artifactory.internal-dev.company.net/artifactory/api/npm/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "//artifactory.internal-dev.company.net/artifactory/api/npm/npm",
			expected: &registryInfo{
				Scheme: isHttp,
				Uri:    "artifactory.internal-dev.company.net/artifactory/api/npm/npm",
			},
		},
		nexusRepo2: {
			data: "registry=http://nexus.corp.org/nexus/content/repositories/npm-group/\n//nexus.corp.org/nexus/content/repositories/npm-group/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "//nexus.corp.org/nexus/content/repositories/npm-group",
			expected: &registryInfo{
				Scheme: isHttp,
				Uri:    "nexus.corp.org/nexus/content/repositories/npm-group",
			},
		},
		nexusRepo3: {
			data: "registry=https://nexus.corp.org/repository/npm-hosted/\n//nexus.corp.org/repository/npm-hosted/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "//nexus.corp.org/repository/npm-hosted",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "nexus.corp.org/repository/npm-hosted",
			},
		},
		gitlab: {
			data: "@company:registry=https://gitlab.com/api/v4/projects/12354452/packages/npm/\n//gitlab.com/api/v4/projects/12354452/packages/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "//gitlab.com/api/v4/projects/12354452/packages/npm",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "gitlab.com/api/v4/projects/12354452/packages/npm",
			},
		},
		github: {
			data: `//npm.pkg.github.com/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//npm.pkg.github.com",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "npm.pkg.github.com",
			},
		},
		azure: {
			data: `//pkgs.dev.azure.com/company/project/_packaging/feed/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//pkgs.dev.azure.com/company/project/_packaging/feed/npm",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry",
			},
		},
		jetbrains: {
			data: `//npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev",
			},
		},
		googleArtifactRegistry: {
			data: `//us-east1-npm.pkg.dev/company-dev-167118/project/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//us-east1-npm.pkg.dev/company-dev-167118/project",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "us-east1-npm.pkg.dev/company-dev-167118/project",
			},
		},
		gemfury: {
			data: `//npm-proxy.fury.io/user/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//npm-proxy.fury.io/user",
			expected: &registryInfo{
				Scheme: isHttps,
				Uri:    "npm-proxy.fury.io/user",
			},
		},
	}

	for group, c := range cases {
		t.Run(group.String(), func(t *testing.T) {
			actual := parseKnownRegistryURI(c.data, c.uri)
			if actual == nil {
				if c.expected != nil {
					t.Errorf("no result for %s", c.data)
				}
				return
			}

			c.expected.RegistryType = group
			if diff := cmp.Diff(c.expected, actual); diff != "" {
				t.Errorf("diff: (-expected +actual)\n%s", diff)
			}
		})
	}
}

func TestNpm_ParseUnknownRegistryUri(t *testing.T) {
	// Not exhaustive, parseUnknownRegistryURI doesn't do much.
	cases := []struct {
		data     string
		uri      string
		expected *registryInfo
	}{
		{
			data: `//npm.fontawesome.com/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "npm.fontawesome.com",
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       unknown,
				Uri:          "npm.fontawesome.com",
			},
		},
		{
			data: "@fortawesome:registry=https://npm.fontawesome.com\n//npm.fontawesome.com/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "npm.fontawesome.com",
			expected: &registryInfo{
				RegistryType: other,
				Scheme:       isHttps,
				Uri:          "npm.fontawesome.com",
			},
		},
	}

	for _, c := range cases {
		actual := parseUnknownRegistryURI(c.data, c.uri)
		if actual == nil {
			t.Errorf("no result for %s", c.data)
			continue
		}

		if diff := cmp.Diff(c.expected, actual); diff != "" {
			t.Errorf("diff: (-expected +actual)\n%s", diff)
		}
	}
}

func TestNpm_ParseRegistryURLScheme(t *testing.T) {
	cases := []struct {
		data           string
		uri            string
		expectedScheme scheme
		expectedUri    string
	}{
		{
			data:           `registry=HTTPS://NPM.EXAMPLE.COM`,
			uri:            "HTTPS://NPM.EXAMPLE.COM",
			expectedScheme: isHttps,
			expectedUri:    "NPM.EXAMPLE.COM",
		},
		{
			data:           `registry=http://npm.example.com/`,
			uri:            "http://npm.example.com",
			expectedScheme: isHttp,
			expectedUri:    "npm.example.com",
		},
		{
			data:           `//repo.example.com/project/npm/:_authToken=abc123`,
			uri:            "repo.example.com/project/npm",
			expectedScheme: unknown,
			expectedUri:    "repo.example.com/project/npm",
		},
		{
			data:           `repo.example.com/project/npm`,
			uri:            "repo.example.com/project/npm",
			expectedScheme: unknown,
			expectedUri:    "repo.example.com/project/npm",
		},
		{
			data:           "registry=httpS://repo.example.com/project/npm\n//repo.example.com/project/npm/:_authToken=abc123",
			uri:            "repo.example.com/project/npm",
			expectedScheme: isHttps,
			expectedUri:    "repo.example.com/project/npm",
		},
		{
			data:           "registry=htTp://repo.example.com/project/npm\n//repo.example.com/project/npm/:_authToken=abc123",
			uri:            "repo.example.com/project/npm",
			expectedScheme: isHttp,
			expectedUri:    "repo.example.com/project/npm",
		},
	}

	for _, c := range cases {
		actualScheme, actualUri := parseRegistryURLScheme(c.data, c.uri)
		if actualScheme != c.expectedScheme {
			t.Errorf("scheme: expected=%s, actual=%s", c.expectedScheme, actualScheme)
		}
		if actualUri != c.expectedUri {
			t.Errorf("uri: expected=%s, actual=%s", c.expectedUri, actualUri)
		}
	}
}
