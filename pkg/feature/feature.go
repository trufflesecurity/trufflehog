package feature

import (
	"net/http"
	"sync/atomic"
)

var (
	ForceSkipBinaries              atomic.Bool
	ForceSkipArchives              atomic.Bool
	GitCloneTimeoutDuration        atomic.Int64
	SkipAdditionalRefs             atomic.Bool
	EnableAPKHandler               atomic.Bool
	UserAgentSuffix                AtomicString
	UseSimplifiedGitlabEnumeration atomic.Bool
	UseGitMirror                   atomic.Bool
	GitlabProjectsPerPage          atomic.Int64
	UseGithubGraphQLAPI            atomic.Bool // use github graphql api to fetch issues, pr's and comments
	HTMLDecoderEnabled             atomic.Bool
	CustomHeaders                  AtomicHeader
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

// AtomicHeader stores an http.Header atomically for global access.
type AtomicHeader struct {
	value atomic.Value
}

// Load returns a clone of the current http.Header value, or nil if unset.
// A clone is returned so callers cannot mutate the shared map and race with
// other readers. http.Header.Clone is cheap for the small (typically 1-3
// entry) header sets configured via --header.
func (ah *AtomicHeader) Load() http.Header {
	if v := ah.value.Load(); v != nil {
		return v.(http.Header).Clone()
	}
	return nil
}

// Store sets the http.Header value.
func (ah *AtomicHeader) Store(h http.Header) {
	ah.value.Store(h)
}
