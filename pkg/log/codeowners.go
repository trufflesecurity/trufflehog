package log

import (
	"strings"
	"unicode"

	"github.com/hmarr/codeowners"
)

type CodeOwners struct {
	rules codeowners.Ruleset
}

func ParseCodeOwners(content string) (*CodeOwners, error) {
	rules, err := codeowners.ParseFile(strings.NewReader(content))
	if err != nil {
		return nil, err
	}
	return &CodeOwners{rules}, nil
}

func (co *CodeOwners) OwnersOf(path string) ([]string, error) {
	path = goPathToFilePath(path)
	rule, err := co.rules.Match(path)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, nil
	}
	owners := make([]string, len(rule.Owners))
	for i, owner := range rule.Owners {
		owners[i] = owner.String()
	}
	return owners, nil
}

func (co *CodeOwners) Owners() []string {
	ownerSet := make(map[string]struct{})
	for _, rule := range co.rules {
		for _, owner := range rule.Owners {
			ownerSet[owner.String()] = struct{}{}
		}
	}

	owners := make([]string, 0, len(ownerSet))
	for owner := range ownerSet {
		owners = append(owners, owner)
	}
	return owners
}

func goPathToFilePath(path string) string {
	// Expected formats:
	// - host/repo_owner/repo_name/path/to/package.func
	// - host/repo_owner/repo_name/repo_version/path/to/package.func
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return path
	}
	parts = parts[3:]
	if len(parts) > 1 && isVersionString(parts[0]) {
		parts = parts[1:]
	}
	return strings.Join(parts, "/")
}

func isVersionString(s string) bool {
	if len(s) <= 1 {
		return false
	}
	if s[0] != 'v' {
		return false
	}
	for _, r := range s[1:] {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
