package github

import (
	"github.com/gobwas/glob"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type filterSet struct {
	include []glob.Glob
	exclude []glob.Glob
	set     map[string]struct{}
}

func newFilterSet(ctx context.Context, include, exclude []string) filterSet {
	includeGlobs := make([]glob.Glob, 0, len(include))
	excludeGlobs := make([]glob.Glob, 0, len(exclude))
	for _, ig := range include {
		g, err := glob.Compile(ig)
		if err != nil {
			ctx.Logger().V(1).Info("invalid include glob", "include_value", ig, "err", err)
			continue
		}
		includeGlobs = append(includeGlobs, g)
	}
	for _, eg := range exclude {
		g, err := glob.Compile(eg)
		if err != nil {
			ctx.Logger().V(1).Info("invalid exclude glob", "exclude_value", eg, "err", err)
			continue
		}
		excludeGlobs = append(excludeGlobs, g)
	}
	return filterSet{include: includeGlobs, exclude: excludeGlobs, set: make(map[string]struct{})}
}

// Add adds the value to the set. True is returned if the value was not
// previously in the set, and false otherwise. It is safe for concurrent use.
func (f *filterSet) Add(v string) bool {
	if f.ignoreValue(v) {
		return false
	}
	if !f.includeValue(v) {
		return false
	}

	if _, ok := f.set[v]; ok {
		return false
	}
	f.set[v] = struct{}{}
	return true
}

// ignoreValue checks the exclude globs for a match. It is safe for concurrent
// use because the slice is written only once on initialization.
func (f *filterSet) ignoreValue(v string) bool {
	for _, g := range f.exclude {
		if g.Match(v) {
			return true
		}
	}
	return false
}

// includeValue checks the include globs for a match. It is safe for concurrent
// use because the slice is written only once on initialization.
func (f *filterSet) includeValue(v string) bool {
	if len(f.include) == 0 {
		return true
	}

	for _, g := range f.include {
		if g.Match(v) {
			return true
		}
	}
	return false
}
