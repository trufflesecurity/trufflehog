package postman

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var subRe = regexp.MustCompile(`\{\{[^{}]+\}\}`)

// DefaultMaxRecursionDepth is the default maximum recursion depth for variable substitution
const DefaultMaxRecursionDepth = 2

type VariableInfo struct {
	value    string
	Metadata Metadata
}

type Substitution struct {
	variables map[string][]VariableInfo
}

func NewSubstitution() *Substitution {
	return &Substitution{
		variables: make(map[string][]VariableInfo),
	}
}

func (sub *Substitution) add(metadata Metadata, key string, value string) {
	sub.variables[key] = append(sub.variables[key], VariableInfo{
		value:    value,
		Metadata: metadata,
	})
}

func (s *Source) keywordCombinations(str string) string {
	data := ""
	for keyword := range s.keywords {
		data += fmt.Sprintf("%s:%s\n", keyword, str)
	}

	return data
}

func (s *Source) formatAndInjectKeywords(data []string) string {
	var ret []string
	for _, d := range data {
		ret = append(ret, s.keywordCombinations(d))
	}
	return strings.Join(ret, "")
}

// buildSubstituteSet creates a set of substitutions for the given data
// maxRecursionDepth is the maximum recursion depth to use for variable substitution
func (s *Source) buildSubstituteSet(
	ctx context.Context,
	metadata Metadata,
	data string,
	maxRecursionDepth int,
) []string {
	var ret []string
	combos := make(map[string]struct{})

	// Call buildSubstitution with initial depth of 0 and the maxRecursionDepth
	s.buildSubstitution(ctx, data, metadata, combos, 0, maxRecursionDepth)

	for combo := range combos {
		ret = append(ret, combo)
	}

	if len(ret) == 0 {
		return []string{data}
	}
	return ret
}

// buildSubstitution performs variable substitution with a maximum recursion depth
// depth is the current recursion depth
// maxRecursionDepth is the maximum recursion depth to use for variable substitution
func (s *Source) buildSubstitution(
	ctx context.Context,
	data string,
	metadata Metadata,
	combos map[string]struct{},
	depth int,
	maxRecursionDepth int,
) {
	// Limit recursion depth to prevent stack overflow
	if depth > maxRecursionDepth {
		ctx.Logger().V(2).Info("Limited recursion depth",
			"depth", depth,
		)
		combos[data] = struct{}{}
		return
	}

	matches := removeDuplicateStr(subRe.FindAllString(data, -1))
	if len(matches) == 0 {
		// No more substitutions to make, add to combos
		combos[data] = struct{}{}
		return
	}

	substitutionMade := false
	for _, match := range matches {
		varName := strings.Trim(match, "{}")
		slices := s.sub.variables[varName]
		if len(slices) == 0 {
			continue
		}

		for _, slice := range slices {
			if slice.Metadata.CollectionInfo.PostmanID != "" &&
				slice.Metadata.CollectionInfo.PostmanID != metadata.CollectionInfo.PostmanID {
				continue
			}

			// Prevent self-referential variables
			if strings.Contains(slice.value, match) {
				continue
			}

			// Use the actual value for substitution, not just the stripped version
			d := strings.ReplaceAll(data, match, slice.value)

			// Only mark substitution as made if we actually changed something
			if d != data {
				substitutionMade = true
				s.buildSubstitution(ctx, d, metadata, combos, depth+1, maxRecursionDepth)
			}
		}
	}

	// If no substitutions were made, add the current data
	if !substitutionMade {
		combos[data] = struct{}{}
	}
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
