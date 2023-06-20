package common

import (
	"regexp"
	"testing"
)

func TestUsernameRegexCheck(t *testing.T) {
	pattern := `?()/\+=\s\n`
	usernameRegexPat := UsernameRegexCheck(pattern)

	expectedRegexPattern := regexp.MustCompile(`(?im)(?:user|usr)\S{0,40}[:=\s]{1,3}[ '"=]{0,1}([^:?()/\+=\s\n]{4,40})['"\n\r]`)

	if usernameRegexPat.compiledRegex.String() != expectedRegexPattern.String() {
		t.Errorf("\n got %v \n want %v", usernameRegexPat.compiledRegex, expectedRegexPattern)
	}

	testString := `username = "dustin123" \n username=dustin123 \n username='dustin123' username:="dustin123"`
	test2String := "username = `dustin123`"

	expectedStr := []string{"dustin123", "dustin123", "dustin123", "dustin123"}
	expected2Str := []string{"dustin123"}

	usernameRegexState := UsernameRegexCheck(pattern)
	usernameRegexMatches := usernameRegexState.Matches([]byte(testString))
	usernameRegex2Matches := usernameRegexState.Matches([]byte(test2String))

	if len(usernameRegexMatches) != len(expectedStr) {
		t.Errorf("\n got %v \n want %v", usernameRegexMatches, expectedStr)
	}

	if len(usernameRegex2Matches) != len(expected2Str) {
		t.Errorf("\n got %v \n want %v", usernameRegex2Matches, expected2Str)
	}
}
