package common

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	usernamePattern = `?()/\+=\s\n`
	passwordPattern = `^<>;.*&|£\n\s`
	usernameRegex   = `(?im)(?:user|usr)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:?()/\+=\s\n]{4,40})\b`
	passwordRegex   = `(?im)(?:pass|password)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:^<>;.*&|£\n\s]{4,40})`
)

func TestEmailRegexCheck(t *testing.T) {
	testEmails := `
		// positive cases
		standard email     = john.doe@example.com
		subdomain email    = jane_doe123@sub.domain.co.us
		organization email = alice.smith@test.org
		test email         = bob@test.name
		with tag email     = user.name+tag@domain.com
		hyphen domain      = info@my-site.net
		service email      = contact@web-service.io
		underscore email   = example_user@domain.info
		department email   = first.last@department.company.edu
		alphanumeric email = user1234@domain.co
		local server email = admin@local-server.local
		dot email          = test.email@my-email-service.xyz
		special char email = special@characters.com
		support email      = support@customer-service.org

		// negative cases
		not an email       = abc.123@z
		looks like email   = test@user <- no domain
		email but not      = user12@service.COM <- capital letters not supported for domain
		random text        = here's some information about local-user@edu user
	`

	expectedStr := []string{
		"john.doe@example.com", "jane_doe123@sub.domain.co.us",
		"alice.smith@test.org", "bob@test.name", "user.name+tag@domain.com",
		"info@my-site.net", "contact@web-service.io", "example_user@domain.info",
		"first.last@department.company.edu", "user1234@domain.co", "admin@local-server.local",
		"test.email@my-email-service.xyz", "special@characters.com", "support@customer-service.org",
	}

	emailRegex := regexp.MustCompile(EmailPattern)

	emailMatches := emailRegex.FindAllString(testEmails, -1)

	assert.Exactly(t, emailMatches, expectedStr)

}

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
