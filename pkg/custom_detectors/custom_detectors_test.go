package custom_detectors

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/protoyaml"
)

const testCustomRegexYaml = `name: Internal bi tool
keywords:
- secret_v1_
- pat_v2_
regex:
  id_pat_example: ([a-zA-Z0-9]{32})
  secret_pat_example: ([a-zA-Z0-9]{32})
verify:
- endpoint: http://localhost:8000/{id_pat_example}
  unsafe: true
  headers:
  - 'Authorization: Bearer {secret_pat_example.0}'
  successRanges:
  - 200-250
  - '288'`

// Helper function to test equality to the data in testCustomRegexYaml.
func assertExpected(t *testing.T, got *custom_detectorspb.CustomRegex) {
	assert.Equal(t, "Internal bi tool", got.Name)
	assert.Equal(t, []string{"secret_v1_", "pat_v2_"}, got.Keywords)
	assert.Equal(t, map[string]string{
		"id_pat_example":     "([a-zA-Z0-9]{32})",
		"secret_pat_example": "([a-zA-Z0-9]{32})",
	}, got.Regex)
	assert.Equal(t, 1, len(got.Verify))
	assert.Equal(t, "http://localhost:8000/{id_pat_example}", got.Verify[0].Endpoint)
	assert.Equal(t, true, got.Verify[0].Unsafe)
	assert.Equal(t, []string{"Authorization: Bearer {secret_pat_example.0}"}, got.Verify[0].Headers)
	assert.Equal(t, []string{"200-250", "288"}, got.Verify[0].SuccessRanges)
}

func TestCustomRegexParsing(t *testing.T) {
	var message custom_detectorspb.CustomRegex

	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testCustomRegexYaml), &message))
	assertExpected(t, &message)
}

func TestCustomDetectorsParsing(t *testing.T) {
	var testYamlConfig string
	// Build a config file using testCustomRegexYaml.
	{
		var lines []string
		for i, line := range strings.Split(testCustomRegexYaml, "\n") {
			if i == 0 {
				lines = append(lines, line)
				continue
			}
			lines = append(lines, "  "+line)
		}
		testYamlConfig = "detectors:\n- " + strings.Join(lines, "\n")
	}

	var messages custom_detectorspb.CustomDetectors
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testYamlConfig), &messages))
	assertExpected(t, messages.Detectors[0])
}
