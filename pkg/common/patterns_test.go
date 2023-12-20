package common

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	usernamePattern = `?()/\+=\s\n`
	passwordPattern = `^<>;.*&|£\n\s`
	usernameRegex   = `(?im)(?:user|usr)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:?()/\+=\s\n'"\s]{4,40})`
	passwordRegex   = `(?im)(?:pass)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:^<>;.*&|£\n\s'"\s]{4,40})`
)

func TestUsernameRegexCheck(t *testing.T) {
	usernameRegexPat := UsernameRegexCheck(usernamePattern)

	expectedRegexPattern := regexp.MustCompile(usernameRegex)

	if usernameRegexPat.compiledRegex.String() != expectedRegexPattern.String() {
		t.Errorf("\n got %v \n want %v", usernameRegexPat.compiledRegex, expectedRegexPattern)
	}

	testString := `username = "johnsmith123"
                   username='johnsmith123'
				   username:="johnsmith123"
                   username = johnsmith123
                   username=johnsmith123`

	expectedStr := []string{"johnsmith123", "johnsmith123", "johnsmith123", "johnsmith123", "johnsmith123"}

	usernameRegexMatches := usernameRegexPat.Matches([]byte(testString))

	assert.Exactly(t, usernameRegexMatches, expectedStr)

}

func TestPasswordRegexCheck(t *testing.T) {
	passwordRegexPat := PasswordRegexCheck(passwordPattern)

	expectedRegexPattern := regexp.MustCompile(passwordRegex)
	assert.Equal(t, passwordRegexPat.compiledRegex, expectedRegexPattern)

	testString := `password = "johnsmith123$!"
	               password='johnsmith123$!'
				   password:="johnsmith123$!"
	               password = johnsmith123$!
	               password=johnsmith123$!
				   PasswordAuthenticator(username, "johnsmith123$!")`

	expectedStr := []string{"johnsmith123$!", "johnsmith123$!", "johnsmith123$!", "johnsmith123$!", "johnsmith123$!",
		"johnsmith123$!"}

	passwordRegexMatches := passwordRegexPat.Matches([]byte(testString))

	assert.Exactly(t, passwordRegexMatches, expectedStr)

}
