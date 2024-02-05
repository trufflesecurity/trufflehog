package glob

import (
	"fmt"

	"github.com/gobwas/glob"
)

// Filter is a generic filter for excluding and including globs (limited
// regular expressions). Exclusion takes precedence if both include and exclude
// lists are provided.
type Filter struct {
	exclude []glob.Glob
	include []glob.Glob
}

type globFilterOpt func(*Filter) error

// WithExcludeGlobs adds exclude globs to the filter.
func WithExcludeGlobs(excludes ...string) globFilterOpt {
	return func(f *Filter) error {
		for _, exclude := range excludes {
			g, err := glob.Compile(exclude)
			if err != nil {
				return fmt.Errorf("invalid exclude glob %q: %w", exclude, err)
			}
			f.exclude = append(f.exclude, g)
		}
		return nil
	}
}

// WithIncludeGlobs adds include globs to the filter.
func WithIncludeGlobs(includes ...string) globFilterOpt {
	return func(f *Filter) error {
		for _, include := range includes {
			g, err := glob.Compile(include)
			if err != nil {
				return fmt.Errorf("invalid include glob %q: %w", include, err)
			}
			f.include = append(f.include, g)
		}
		return nil
	}
}

// NewGlobFilter creates a new Filter with the provided options.
func NewGlobFilter(opts ...globFilterOpt) (*Filter, error) {
	filter := &Filter{}
	for _, opt := range opts {
		if err := opt(filter); err != nil {
			return nil, err
		}
	}
	return filter, nil
}

// ShouldInclude returns whether the object is in the include list or not in
// the exclude list (exclude taking precedence).
func (f *Filter) ShouldInclude(object string) bool {
	if f == nil {
		return true
	}
	exclude, include := len(f.exclude), len(f.include)
	if exclude == 0 && include == 0 {
		return true
	} else if exclude > 0 && include == 0 {
		return f.shouldIncludeFromExclude(object)
	} else if exclude == 0 && include > 0 {
		return f.shouldIncludeFromInclude(object)
	} else {
		if ok, err := f.shouldIncludeFromBoth(object); err == nil {
			return ok
		}
		// Ambiguous case.
		return false
	}
}

// shouldIncludeFromExclude checks for explicitly excluded paths. This should
// only be called when the include list is empty.
func (f *Filter) shouldIncludeFromExclude(object string) bool {
	for _, g := range f.exclude {
		if g.Match(object) {
			return false
		}
	}
	return true
}

// shouldIncludeFromInclude checks for explicitly included paths. This should
// only be called when the exclude list is empty.
func (f *Filter) shouldIncludeFromInclude(object string) bool {
	for _, g := range f.include {
		if g.Match(object) {
			return true
		}
	}
	return false
}

// shouldIncludeFromBoth checks for either excluded or included paths. Exclusion
// takes precedence. If neither list contains the object, true is returned.
func (f *Filter) shouldIncludeFromBoth(object string) (bool, error) {
	// Exclude takes precedence. If we find the object in the exclude list,
	// we should not match.
	for _, g := range f.exclude {
		if g.Match(object) {
			return false, nil
		}
	}
	// If we find the object in the include list, we should match.
	for _, g := range f.include {
		if g.Match(object) {
			return true, nil
		}
	}
	// If we find it in neither, return an error to let the caller decide.
	return false, fmt.Errorf("ambiguous match")
}
