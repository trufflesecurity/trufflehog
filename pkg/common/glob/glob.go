package common

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
	// If an object is not found in either of the filters, return this
	// value in Pass.
	notFoundPassBehavior bool
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

// WithDefaultDeny configures the filter to deny objects that are not found
// in either exclude or include filter (in the ambiguous case where both are
// configured).
func WithDefaultDeny() globFilterOpt {
	return func(f *Filter) error {
		f.notFoundPassBehavior = true
		return nil
	}
}

// WithDefaultAllow configures the filter to allow objects that are not found
// in either exclude or include filter (in the ambiguous case where both are
// configured).
func WithDefaultAllow() globFilterOpt {
	return func(f *Filter) error {
		f.notFoundPassBehavior = false
		return nil
	}
}

// NewGlobFilter creates a new Filter with the provided options.
func NewGlobFilter(opts ...globFilterOpt) (*Filter, error) {
	filter := &Filter{notFoundPassBehavior: true}
	for _, opt := range opts {
		if err := opt(filter); err != nil {
			return nil, err
		}
	}
	return filter, nil
}

// Pass returns whether the object is not in the include list or in the exclude
// list.
func (f *Filter) Pass(object string) bool {
	if f == nil {
		return false
	}
	exclude, include := len(f.exclude), len(f.include)
	if exclude == 0 && include == 0 {
		return false
	} else if exclude > 0 && include == 0 {
		return f.passExclude(object)
	} else if exclude == 0 && include > 0 {
		return f.passInclude(object)
	} else {
		if pass, err := f.passExcludeInclude(object); err == nil {
			return pass
		}
		// Ambiguous case.
		return f.notFoundPassBehavior
	}
}

// passExclude checks for explicitly excluded paths. This should only be called
// when the include list is empty.
func (f *Filter) passExclude(object string) bool {
	for _, glob := range f.exclude {
		if glob.Match(object) {
			return true
		}
	}
	return false
}

// passInclude checks for explicitly included paths. This should only be called
// when the exclude list is empty.
func (f *Filter) passInclude(object string) bool {
	for _, glob := range f.include {
		if glob.Match(object) {
			return false
		}
	}
	return true
}

// passExcludeInclude checks for either excluded or included paths. Exclusion
// takes precedence. If neither list contains the object, true is returned.
func (f *Filter) passExcludeInclude(object string) (bool, error) {
	// Exclude takes precedence. If we find the object in the exclude list,
	// we should pass.
	for _, glob := range f.exclude {
		if glob.Match(object) {
			return true, nil
		}
	}
	// If we find the object in the include list, we should not pass.
	for _, glob := range f.include {
		if glob.Match(object) {
			return false, nil
		}
	}
	// If we find it in neither, return an error to let the caller decide.
	return false, fmt.Errorf("ambiguous match")
}
