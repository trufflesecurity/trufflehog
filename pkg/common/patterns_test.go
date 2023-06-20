package common

import (
	"regexp"
	"testing"
)

const (
	pattern = `?()/\+=\s\n`
	regex   = `(?im)(?:user|usr)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:?()/\+=\s\n]{4,40})\b`
)

func TestUsernameRegexCheck(t *testing.T) {
	usernameRegexPat := UsernameRegexCheck(pattern)

	expectedRegexPattern := regexp.MustCompile(regex)

	if usernameRegexPat.compiledRegex.String() != expectedRegexPattern.String() {
		t.Errorf("\n got %v \n want %v", usernameRegexPat.compiledRegex, expectedRegexPattern)
	}

	testString := `username = "johnsmith123" \n username='johnsmith123' username:="johnsmith123" username = johnsmith123 username=dustin123`

	expectedStr := []string{"johnsmith123", "johnsmith123", "johnsmith123", "johnsmith123", "johnsmith123"}

	usernameRegexState := UsernameRegexCheck(pattern)
	usernameRegexMatches := usernameRegexState.Matches([]byte(testString))

	if len(usernameRegexMatches) != len(expectedStr) {
		t.Errorf("\n got %v \n want %v", usernameRegexMatches, expectedStr)
	}

}
