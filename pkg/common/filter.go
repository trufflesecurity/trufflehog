package common

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// IgnoreFileName is the filename trufflehog auto-discovers at scan roots, in
// the spirit of .gitignore / .gitleaksignore. Patterns inside use the same
// gitignore-style globs (one per line, '#' for comments) and are appended to
// the exclude rules used by the scan filter.
//
// See https://github.com/trufflesecurity/trufflehog/issues/2687.
const IgnoreFileName = ".trufflehogignore"

type Filter struct {
	include *FilterRuleSet
	exclude *FilterRuleSet
}

type FilterRuleSet []regexp.Regexp

// FilterEmpty returns a Filter that always passes.
func FilterEmpty() *Filter {
	filter, err := FilterFromFiles("", "")
	if err != nil {
		context.Background().Logger().Error(err, "could not create empty filter")
		os.Exit(1)
	}
	return filter
}

// FilterFromFiles creates a Filter using the rules in the provided include and exclude files.
func FilterFromFiles(includeFilterPath, excludeFilterPath string) (*Filter, error) {
	includeRules, err := FilterRulesFromFile(includeFilterPath)
	if err != nil {
		return nil, fmt.Errorf("could not create include rules: %s", err)
	}
	excludeRules, err := FilterRulesFromFile(excludeFilterPath)
	if err != nil {
		return nil, fmt.Errorf("could not create exclude rules: %s", err)
	}

	// If no includeFilterPath is provided, every pattern should pass the include rules.
	if includeFilterPath == "" {
		includeRules = &FilterRuleSet{*regexp.MustCompile("")}
	}

	filter := &Filter{
		include: includeRules,
		exclude: excludeRules,
	}

	return filter, nil
}

// FilterRulesFromFile loads the list of regular expression filter rules in `source` and creates a FilterRuleSet.
func FilterRulesFromFile(source string) (*FilterRuleSet, error) {
	rules := FilterRuleSet{}
	if source == "" {
		return &rules, nil
	}

	commentPattern := regexp.MustCompile(`^\s*#`)
	emptyLinePattern := regexp.MustCompile(`^\s*$`)

	file, err := os.Open(source)
	logger := context.Background().Logger().WithValues("file", source)
	if err != nil {
		logger.Error(err, "unable to open filter file", "file", source)
		os.Exit(1)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			logger.Error(err, "unable to close filter file")
			os.Exit(1)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if commentPattern.MatchString(line) {
			continue
		}
		if emptyLinePattern.MatchString(line) {
			continue
		}
		pattern, err := regexp.Compile(line)
		if err != nil {
			return nil, fmt.Errorf("can not compile regular expression: %s", line)
		}
		rules = append(rules, *pattern)
	}
	return &rules, nil
}

// Pass returns true if the include FilterRuleSet matches the pattern and the exclude FilterRuleSet does not match.
func (filter *Filter) Pass(object string) bool {
	if filter == nil {
		return true
	}

	excluded := filter.exclude.Matches(object)
	included := filter.include.Matches(object)

	return !excluded && included
}

// Matches will return true if any of the regular expressions in the FilterRuleSet match the pattern.
func (rules *FilterRuleSet) Matches(object string) bool {
	if rules == nil {
		return false
	}
	for _, rule := range *rules {
		if rule.MatchString(object) {
			return true
		}
	}
	return false
}

// ShouldExclude return true if any regular expressions in the exclude FilterRuleSet matches the path.
func (filter *Filter) ShouldExclude(path string) bool {
	return filter.exclude.Matches(path)
}

// AddTrufflehogIgnoreFiles loads .trufflehogignore files from each of the
// supplied scan roots (when present) and appends their patterns to the
// filter's exclude rules. An empty or missing ignore file is a no-op. Patterns
// use gitignore-style globs (one per line, '#' for comments) and are
// converted to anchored regexes before being added; this gives users the
// .gitleaksignore-style UX they want without inventing a new fingerprint
// scheme. Returns the slice of paths actually loaded so callers can log them.
//
// See https://github.com/trufflesecurity/trufflehog/issues/2687.
func (filter *Filter) AddTrufflehogIgnoreFiles(scanRoots ...string) ([]string, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.exclude == nil {
		empty := FilterRuleSet{}
		filter.exclude = &empty
	}

	var loaded []string
	seen := make(map[string]struct{})
	for _, root := range scanRoots {
		if root == "" {
			continue
		}
		path := filepath.Join(root, IgnoreFileName)
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		extra, err := filterRulesFromGlobFile(path)
		if err != nil {
			return loaded, err
		}
		if extra == nil {
			continue
		}
		*filter.exclude = append(*filter.exclude, *extra...)
		loaded = append(loaded, path)
	}
	return loaded, nil
}

// filterRulesFromGlobFile reads a gitignore-style file and converts each entry
// to an anchored regex. Returns nil when the file does not exist (so callers
// can treat ignore-file discovery as best-effort). When the supplied scan
// root is itself a regular file (e.g. trufflehog filesystem scan invoked on a
// single file), the join produces a path whose parent isn't a directory; we
// surface that as "not present" rather than an error so the auto-discovery
// stays out of the way.
func filterRulesFromGlobFile(path string) (*FilterRuleSet, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		// "<path>/.trufflehogignore: not a directory" when the scan root is a
		// regular file rather than a directory. Treat as no ignore file.
		if strings.Contains(err.Error(), "not a directory") {
			return nil, nil
		}
		return nil, fmt.Errorf("unable to open %s: %w", path, err)
	}
	defer file.Close()

	rules := FilterRuleSet{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "!"-prefixed re-include patterns are not supported in this initial
		// implementation; surface a clear error so users don't silently get
		// wrong behavior. Plain patterns work as expected.
		if strings.HasPrefix(line, "!") {
			return nil, fmt.Errorf(
				"%s: re-include patterns (lines starting with '!') are not yet supported (offending line: %q)",
				path, line,
			)
		}
		pattern, err := globToRegex(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		rules = append(rules, *pattern)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &rules, nil
}

// globToRegex converts a gitignore-style glob pattern into a compiled
// regular expression suitable for the existing FilterRuleSet matching.
//
// Supported syntax:
//   - "*"      matches any run of characters that are not "/"
//   - "**/"    matches zero or more path segments (so "a/**/b" matches "a/b" and "a/x/b")
//   - "/**"    at end matches everything under the prefix
//   - "?"      matches any single character that is not "/"
//   - "/" at start anchors at the scan root
//   - "/" at end matches a directory and everything under it
//
// Unsupported (returns an error so the user is not silently fooled):
//   - character classes ("[...]")
//   - "!"-prefixed re-includes (handled by the caller)
func globToRegex(glob string) (*regexp.Regexp, error) {
	if strings.ContainsAny(glob, "[]") {
		return nil, fmt.Errorf("character class globs ('[...]') are not yet supported (offending line: %q)", glob)
	}

	anchored := strings.HasPrefix(glob, "/")
	trailingSlash := strings.HasSuffix(glob, "/")
	body := strings.TrimPrefix(glob, "/")
	body = strings.TrimSuffix(body, "/")

	var b strings.Builder
	if anchored {
		b.WriteString("^")
	} else {
		// non-anchored entries match anywhere in the path, just like .gitignore.
		b.WriteString("(?:^|/)")
	}

	// Walk the body, collapsing "/**/" runs into an "any-number-of-dirs"
	// regex fragment. This is the standard gitignore semantic where
	// "a/**/b" matches "a/b" as well as "a/x/b" or "a/x/y/b".
	i := 0
	for i < len(body) {
		// "/**/" → zero or more path segments + "/"
		if i+3 < len(body) && body[i] == '/' && body[i+1] == '*' && body[i+2] == '*' && body[i+3] == '/' {
			b.WriteString("(?:/|/.*/)")
			i += 4
			continue
		}
		// "**/" at start of body → zero or more path segments
		if i == 0 && i+2 < len(body) && body[i] == '*' && body[i+1] == '*' && body[i+2] == '/' {
			b.WriteString("(?:|.*/)")
			i += 3
			continue
		}
		// trailing "/**" → everything under
		// i indexes the leading '/', so i+2 must be the last valid byte ('*'),
		// which means i+3 == len(body). Using i+2 == len(body) here would index
		// past the end of the slice when the condition fired.
		if i+3 == len(body) && body[i] == '/' && body[i+1] == '*' && body[i+2] == '*' {
			b.WriteString("/.*")
			i += 3
			continue
		}
		c := body[i]
		switch c {
		case '*':
			if i+1 < len(body) && body[i+1] == '*' {
				b.WriteString(".*")
				i += 2
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '{', '}', '$', '^', '\\':
			b.WriteString(regexp.QuoteMeta(string(c)))
		default:
			b.WriteByte(c)
		}
		i++
	}

	if trailingSlash {
		b.WriteString("(?:/|$)")
	} else {
		b.WriteString("(?:$|/)")
	}

	return regexp.Compile(b.String())
}
