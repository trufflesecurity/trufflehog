package gitlab

import (
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// project represents GitLab project metadata.
type project struct {
	id    int64
	name  string
	owner string
}

// projectMetadataCache stores project metadata with thread-safe access.
type projectMetadataCache struct {
	mu    sync.RWMutex
	cache *expirable.LRU[string, *project]
}

// NewProjectMetadataCache initializes a new project metadata cache
// with a 30k entry limit and a 60-minute expiration.
func NewProjectMetadataCache() *projectMetadataCache {
	return &projectMetadataCache{
		cache: expirable.NewLRU[string, *project](
			15000, // upto 15000 entries
			nil,
			60*time.Minute, // time-based expiration - 1 hour
		),
	}
}

func (c *projectMetadataCache) get(repo string) (*project, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cache.Get(repo)
}

func (c *projectMetadataCache) set(repo string, proj *project) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Add(repo, proj)
}
