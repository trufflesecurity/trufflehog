package postgresurl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := map[string]paramsMap{
		"postgres://":                {},
		"postgres://hostname.remote": {"host": "hostname.remote"},
		"postgres://[::1]:1234":      {"host": "::1", "port": "1234"},
		"postgres://localhost/a%2Fb": {"dbname": "a/b", "host": "localhost"},
		"postgres://username:top%20secret@hostname.remote:1234/database": {
			"dbname":   "database",
			"host":     "hostname.remote",
			"password": "top secret",
			"port":     "1234",
			"user":     "username",
		},
		"postgres://localhost/postgres?require_auth=gss&sslmode=require": {
			"dbname":       "postgres",
			"host":         "localhost",
			"require_auth": "gss",
			"sslmode":      "require",
		},
	}

	for url := range tests {
		t.Run("test "+url, func(t *testing.T) {
			params, err := Parse(url)
			assert.NoError(t, err)
			assert.Equal(t, tests[url], params)
			assert.Equal(t, ParamsToConnStr(tests[url]), ParamsToConnStr(params))
		})
	}

	errors := map[string]string{
		"":                       "invalid connection protocol:",
		"http://hostname.remote": "invalid connection protocol: http",
		"postgresql://%2Fvar%2Flib%2Fpostgresql/dbname": `invalid URL escape "%2F"`,
	}

	for url := range errors {
		t.Run("error "+url, func(t *testing.T) {
			_, err := Parse(url)
			assert.ErrorContains(t, err, errors[url])
		})
	}
}

func TestParamsToConnStr(t *testing.T) {
	assert.Equal(t, "", ParamsToConnStr(paramsMap{}))

	assert.Equal(
		t,
		"dbname='postgres' host='localhost' require_auth='gss' sslmode='require'",
		ParamsToConnStr(paramsMap{"dbname": "postgres", "host": "localhost", "require_auth": "gss", "sslmode": "require"}),
	)

	assert.Equal(
		t,
		`dbname='post\'gres' host='local\\host'`,
		ParamsToConnStr(paramsMap{"dbname": "post'gres", "host": "local\\host"}),
	)
}
