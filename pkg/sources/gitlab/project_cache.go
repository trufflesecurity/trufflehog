package gitlab

import "sync"

type project struct {
	id    int64
	name  string
	owner string
}

type repoToProjectCache struct {
	sync.RWMutex

	cache map[string]*project
}

func (r *repoToProjectCache) get(repo string) (*project, bool) {
	r.RLock()
	defer r.RUnlock()
	proj, ok := r.cache[repo]
	return proj, ok
}

func (r *repoToProjectCache) set(repo string, proj *project) {
	r.Lock()
	defer r.Unlock()

	r.cache[repo] = proj
}
