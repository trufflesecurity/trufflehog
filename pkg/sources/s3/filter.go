package s3

import (
	"errors"
	"path"
	"slices"
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

	// Lowercase extensions without a leading dot, sorted and deduplicated. At most
	// one is populated.
	includeExtensions []string
	excludeExtensions []string
}

// newObjectFilter builds a filter from the configured lists. Extensions may be
// written with or without a leading dot and in any case. Entries are trimmed and
// blank ones dropped, since a padded entry would match nothing and an empty prefix
// would match every key.
func newObjectFilter(includePrefixes, excludePrefixes, includeExtensions, excludeExtensions []string) (*objectFilter, error) {
	// Compare the cleaned lists rather than the raw ones, so that a list holding
	// nothing but blanks does not count as populated.
	include, exclude := cleanExtensions(includeExtensions), cleanExtensions(excludeExtensions)
	if len(include) > 0 && len(exclude) > 0 {
		return nil, errors.New("either an extension include list or an extension exclude list can be specified, but not both")
	}

	return &objectFilter{
		includePrefixes:   cleanEntries(includePrefixes, strings.TrimSpace),
		excludePrefixes:   cleanEntries(excludePrefixes, strings.TrimSpace),
		includeExtensions: include,
		excludeExtensions: exclude,
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
		return !slices.Contains(f.excludeExtensions, ext)
	}
	return slices.Contains(f.includeExtensions, ext)
}

// isConfigured reports whether any filtering is in effect.
func (f *objectFilter) isConfigured() bool {
	if f == nil {
		return false
	}
	return len(f.includePrefixes) > 0 || len(f.excludePrefixes) > 0 ||
		len(f.includeExtensions) > 0 || len(f.excludeExtensions) > 0
}

// normalizeExtension trims either side of the dot, so that a padded configured
// value cannot silently match nothing. It runs on configured values and on the
// extension read from a key alike, keeping both sides of a comparison normalized
// the same way.
func normalizeExtension(ext string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ext), ".")))
}

// cleanExtensions normalizes configured extensions and sorts them, so that logging
// the effective filter is stable rather than following the order they were given.
func cleanExtensions(values []string) []string {
	exts := cleanEntries(values, normalizeExtension)
	slices.Sort(exts)
	return slices.Compact(exts)
}

// cleanEntries normalizes each entry and drops the ones that come out empty,
// returning nil when nothing is left.
func cleanEntries(values []string, normalize func(string) string) []string {
	if len(values) == 0 {
		return nil
	}
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalize(value); normalized != "" {
			kept = append(kept, normalized)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}
