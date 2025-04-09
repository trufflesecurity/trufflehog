package common

import (
	"bufio"
	"fmt"
	"os"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

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
