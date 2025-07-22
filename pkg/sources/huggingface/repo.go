package huggingface

import (
	"fmt"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
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
	owner        string
	name         string
	fullName     string
	visibility   source_metadatapb.Visibility
	resourceType resourceType
}

func (s *Source) cloneRepo(
	ctx context.Context,
	repoURL string,
) (string, *gogit.Repository, error) {
	var (
		path string
		repo *gogit.Repository
		err  error
	)

	switch s.conn.GetCredential().(type) {
	case *sourcespb.Huggingface_Unauthenticated:
		ctx.Logger().V(2).Info("cloning repo without authentication", "repo_url", repoURL)
		path, repo, err = git.CloneRepoUsingUnauthenticated(ctx, repoURL)
		if err != nil {
			return "", nil, err
		}
	case *sourcespb.Huggingface_Token:
		ctx.Logger().V(2).Info("cloning repo with token authentication", "repo_url", repoURL)
		path, repo, err = git.CloneRepoUsingToken(ctx, s.huggingfaceToken, repoURL, "", true)
		if err != nil {
			return "", nil, err
		}
	default:
		return "", nil, fmt.Errorf("unhandled credential type for repo %s: %T", repoURL, s.conn.GetCredential())
	}
	return path, repo, nil
}
