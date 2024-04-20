package postman

import (
	"fmt"
	"regexp"
	"strings"
)

var subRe = regexp.MustCompile(`\{\{[^{}]+\}\}`)

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

func (s *Source) buildSubstitueSet(metadata Metadata, data string) []string {
	var ret []string
	combos := make(map[string]struct{})

	s.buildSubstitution(data, metadata, &combos)

	for combo := range combos {
		ret = append(ret, combo)
	}

	if len(ret) == 0 {
		return []string{data}
	}
	return ret
}

func (s *Source) buildSubstitution(data string, metadata Metadata, combos *map[string]struct{}) {
	matches := removeDuplicateStr(subRe.FindAllString(data, -1))
	for _, match := range matches {
		for _, slice := range s.sub.variables[strings.Trim(match, "{}")] {
			if slice.Metadata.CollectionInfo.PostmanID != "" && slice.Metadata.CollectionInfo.PostmanID != metadata.CollectionInfo.PostmanID {
				continue
			}
			// to ensure we don't infinitely recurse, we will trim all `{{}}` from the values before replacement
			d := strings.ReplaceAll(data, match, strings.Trim(slice.value, "{}"))
			s.buildSubstitution(d, metadata, combos)
		}
	}

	if len(matches) == 0 {
		// add to combos
		(*combos)[data] = struct{}{}
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
