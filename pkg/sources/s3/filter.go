package s3

import (
	"errors"
	"path"
	"strings"
)

// objectFilter narrows a scan to the configured key prefixes and file extensions.
// An object must pass both axes to be scanned.
//
// The two axes treat a populated include and exclude list differently. Prefixes
// accept both at once, so a scan can cover a subtree minus one directory, and
// exclusion wins on a key that matches both. Extensions accept only one, because
// naming the extensions to scan already excludes every other one; both together is
// rejected in Init. Buckets reject both lists too, so prefixes are the exception.
//
// The zero value and a nil *objectFilter both include everything.
type objectFilter struct {
	includePrefixes []string
	excludePrefixes []string

	// Keyed by lowercase extension without a leading dot. At most one is populated.
	includeExtensions map[string]struct{}
	excludeExtensions map[string]struct{}
}

// newObjectFilter builds a filter from the configured lists. Extensions may be
// written with or without a leading dot and in any case. Blank entries are dropped,
// since an empty prefix would match every key.
func newObjectFilter(includePrefixes, excludePrefixes, includeExtensions, excludeExtensions []string) (*objectFilter, error) {
	if len(includeExtensions) > 0 && len(excludeExtensions) > 0 {
		return nil, errors.New("either an extension include list or an extension exclude list can be specified, but not both")
	}

	return &objectFilter{
		includePrefixes:   nonBlank(includePrefixes),
		excludePrefixes:   nonBlank(excludePrefixes),
		includeExtensions: extensionSet(includeExtensions),
		excludeExtensions: extensionSet(excludeExtensions),
	}, nil
}

// shouldInclude reports whether the object key passes both filter axes.
func (f *objectFilter) shouldInclude(key string) bool {
	if f == nil {
		return true
	}
	return f.passesPrefixes(key) && f.passesExtensions(key)
}

func (f *objectFilter) passesPrefixes(key string) bool {
	for _, prefix := range f.excludePrefixes {
		if strings.HasPrefix(key, prefix) {
			return false
		}
	}
	if len(f.includePrefixes) == 0 {
		return true
	}
	for _, prefix := range f.includePrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// passesExtensions applies the extension axis. A key with no extension matches no
// configured entry, so it fails a populated include list and passes an exclude list.
func (f *objectFilter) passesExtensions(key string) bool {
	if len(f.includeExtensions) == 0 && len(f.excludeExtensions) == 0 {
		return true
	}

	// path.Ext rather than filepath.Ext: S3 keys always separate on "/", whatever
	// the host OS uses.
	ext := normalizeExtension(path.Ext(key))
	if len(f.excludeExtensions) > 0 {
		_, excluded := f.excludeExtensions[ext]
		return !excluded
	}
	_, included := f.includeExtensions[ext]
	return included
}

func normalizeExtension(ext string) string {
	return strings.ToLower(strings.TrimPrefix(ext, "."))
}

func extensionSet(exts []string) map[string]struct{} {
	if len(exts) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(exts))
	for _, ext := range exts {
		if normalized := normalizeExtension(ext); normalized != "" {
			set[normalized] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func nonBlank(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			kept = append(kept, value)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}
