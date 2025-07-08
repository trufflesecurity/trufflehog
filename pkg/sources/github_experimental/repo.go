package github_experimental

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/go-github/v67/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

type repoInfoCache struct {
	mu    sync.RWMutex
	cache map[string]repoInfo
}

func newRepoInfoCache() repoInfoCache {
	return repoInfoCache{
		cache: make(map[string]repoInfo),
	}
}

func (r *repoInfoCache) put(repoURL string, info repoInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[repoURL] = info
}

func (r *repoInfoCache) get(repoURL string) (repoInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.cache[repoURL]
	return info, ok
}

type repoInfo struct {
	owner      string
	name       string
	fullName   string
	hasWiki    bool // the repo is _likely_ to have a wiki (see the comment on wikiIsReachable func).
	size       int
	visibility source_metadatapb.Visibility
}

func (s *Source) cacheRepoInfo(r *github.Repository) {
	info := repoInfo{
		owner:    r.GetOwner().GetLogin(),
		name:     r.GetName(),
		fullName: r.GetFullName(),
		hasWiki:  r.GetHasWiki(),
		size:     r.GetSize(),
	}
	if r.GetPrivate() {
		info.visibility = source_metadatapb.Visibility_private
	} else {
		info.visibility = source_metadatapb.Visibility_public
	}
	s.repoInfoCache.put(r.GetCloneURL(), info)
}

func (s *Source) normalizeRepo(repo string) (string, error) {
	// If there's a '/', assume it's a URL and try to normalize it.
	if strings.ContainsRune(repo, '/') {
		return giturl.NormalizeGithubRepo(repo)
	}

	return "", fmt.Errorf("no repositories found for %s", repo)
}
