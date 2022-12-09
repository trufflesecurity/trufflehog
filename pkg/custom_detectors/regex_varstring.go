package custom_detectors

import (
	"regexp"
	"strconv"
	"strings"
)

// nameGroupRegex matches `{ name . group }` ignoring any whitespace.
var nameGroupRegex = regexp.MustCompile(`{\s*([a-zA-Z0-9-_]+)\s*(\.\s*[0-9]*)?\s*}`)

// RegexVarString is a string with embedded {name.group} variables. A name may
// only contain alphanumeric, hyphen, and underscore characters. Group is
// optional but if provided it must be a non-negative integer. If the group is
// omitted it defaults to 0.
type RegexVarString struct {
	original string
	// map from name to group
	variables map[string]int
}

func NewRegexVarString(original string) RegexVarString {
	variables := make(map[string]int)

	matches := nameGroupRegex.FindAllStringSubmatch(original, -1)
	for _, match := range matches {
		name, group := match[1], 0
		// The second match will start with a period followed by any number
		// of whitespace.
		if len(match[2]) > 1 {
			g, err := strconv.Atoi(strings.TrimSpace(match[2][1:]))
			if err != nil {
				continue
			}
			group = g
		}
		variables[name] = group
	}

	return RegexVarString{
		original:  original,
		variables: variables,
	}
}
