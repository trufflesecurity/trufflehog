//go:build detectors
// +build detectors

package jdbc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func parseSqliteTest(subname string) (jdbc, error) {
	j, err := parseSqlite(subname)
	if err != nil {
		return j, err
	}
	j.(*sqliteJDBC).testing = true
	return j, err
}

func TestParseSqlite(t *testing.T) {
	type testStruct struct {
		input   string
		wantErr bool
	}
	tests := []struct {
		input   string
		wantErr bool
	}{
		{input: "", wantErr: true},
		{input: ":memory:"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			j, err := parseSqliteTest(test.input)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.True(t, j.ping())
			}
		})
	}
}
