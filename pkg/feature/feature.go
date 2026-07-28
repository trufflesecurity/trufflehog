package feature

import (
	"sync/atomic"
)

var (
	ForceSkipBinaries                        atomic.Bool
	ForceSkipArchives                        atomic.Bool
	GitCloneTimeoutDuration                  atomic.Int64
	SkipAdditionalRefs                       atomic.Bool
	EnableAPKHandler                         atomic.Bool
	UserAgentSuffix                          AtomicString
	UseSimplifiedGitlabEnumeration           atomic.Bool
	UseGitMirror                             atomic.Bool
	GitlabProjectsPerPage                    atomic.Int64
	UseGithubGraphQLAPI                      atomic.Bool // use github graphql api to fetch issues, pr's and comments
	HTMLDecoderEnabled                       atomic.Bool
	PineconeDetectorEnabled                  atomic.Bool
	CloudinaryDetectorEnabled                atomic.Bool
	GitLabOAuthDetectorEnabled               atomic.Bool
	SonarCloudV2DetectorEnabled              atomic.Bool
	EnigmaDetectorEnabled                    atomic.Bool
	DatadogApiKeyDetectorEnabled             atomic.Bool
	TlyDetectorEnabled                       atomic.Bool
	WitDetectorEnabled                       atomic.Bool
	RevDetectorEnabled                       atomic.Bool
	UserDetectorEnabled                      atomic.Bool
	BraintrustDetectorEnabled                atomic.Bool
	PgAnalyzeReadKeyDetectorEnabled          atomic.Bool
	RedHatPyxisDetectorEnabled               atomic.Bool
	OctopusDeployDetectorEnabled             atomic.Bool
	DropUnverifiedJWTResults                 atomic.Bool
	OpenRouterDetectorEnabled                atomic.Bool
	NewRelicInsightsInsertKeyDetectorEnabled atomic.Bool
	DuffelTokenDetectorEnabled               atomic.Bool
	ShippoDetectorEnabled                    atomic.Bool
	IPInfoDetectorEnabled                    atomic.Bool
	LobDetectorEnabled                       atomic.Bool
	HashiCorpVaultBatchTokenDetectorEnabled  atomic.Bool
	HashiCorpVaultTokenDetectorEnabled       atomic.Bool
	CloudflareApiTokenV2DetectorEnabled      atomic.Bool
	CloudflareGlobalApiKeyV2DetectorEnabled  atomic.Bool
	DuoDetectorEnabled                       atomic.Bool
)

type AtomicString struct {
	value atomic.Value
}

// Load returns the current value of the atomic string
func (as *AtomicString) Load() string {
	if v := as.value.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Store sets the value of the atomic string
func (as *AtomicString) Store(newValue string) {
	as.value.Store(newValue)
}

// Swap atomically swaps the current string with a new one and returns the old value
func (as *AtomicString) Swap(newValue string) string {
	oldValue := as.Load()
	as.Store(newValue)
	return oldValue
}
