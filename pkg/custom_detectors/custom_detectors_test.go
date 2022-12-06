package custom_detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/protoyaml"
)

func TestCustomRegexTemplateParsing(t *testing.T) {
	testCustomRegexTemplateYaml := `name: Internal bi tool
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

	var got custom_detectorspb.CustomRegex
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testCustomRegexTemplateYaml), &got))
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

func TestCustomRegexWebhookParsing(t *testing.T) {
	testCustomRegexWebhookYaml := `name: Internal bi tool
keywords:
- secret_v1_
- pat_v2_
regex:
  id_pat_example: ([a-zA-Z0-9]{32})
  secret_pat_example: ([a-zA-Z0-9]{32})
verify:
- endpoint: http://localhost:8000/
  unsafe: true
  headers:
  - 'Authorization: Bearer token'`

	var got custom_detectorspb.CustomRegex
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testCustomRegexWebhookYaml), &got))
	assert.Equal(t, "Internal bi tool", got.Name)
	assert.Equal(t, []string{"secret_v1_", "pat_v2_"}, got.Keywords)
	assert.Equal(t, map[string]string{
		"id_pat_example":     "([a-zA-Z0-9]{32})",
		"secret_pat_example": "([a-zA-Z0-9]{32})",
	}, got.Regex)
	assert.Equal(t, 1, len(got.Verify))
	assert.Equal(t, "http://localhost:8000/", got.Verify[0].Endpoint)
	assert.Equal(t, true, got.Verify[0].Unsafe)
	assert.Equal(t, []string{"Authorization: Bearer token"}, got.Verify[0].Headers)
}

// TestCustomDetectorsParsing tests the full `detectors` configuration.
func TestCustomDetectorsParsing(t *testing.T) {
	// TODO: Support both template and webhook.
	testYamlConfig := `detectors:
- name: Internal bi tool
  keywords:
  - secret_v1_
  - pat_v2_
  regex:
    id_pat_example: ([a-zA-Z0-9]{32})
    secret_pat_example: ([a-zA-Z0-9]{32})
  verify:
  - endpoint: http://localhost:8000/
    unsafe: true
    headers:
    - 'Authorization: Bearer token'`

	var messages custom_detectorspb.CustomDetectors
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testYamlConfig), &messages))
	assert.Equal(t, 1, len(messages.Detectors))

	got := messages.Detectors[0]
	assert.Equal(t, "Internal bi tool", got.Name)
	assert.Equal(t, []string{"secret_v1_", "pat_v2_"}, got.Keywords)
	assert.Equal(t, map[string]string{
		"id_pat_example":     "([a-zA-Z0-9]{32})",
		"secret_pat_example": "([a-zA-Z0-9]{32})",
	}, got.Regex)
	assert.Equal(t, 1, len(got.Verify))
	assert.Equal(t, "http://localhost:8000/", got.Verify[0].Endpoint)
	assert.Equal(t, true, got.Verify[0].Unsafe)
	assert.Equal(t, []string{"Authorization: Bearer token"}, got.Verify[0].Headers)
}

func TestCustomDetectorsKeywordValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{
			name:    "Test empty list of keywords",
			input:   []string{},
			wantErr: true,
		},
		{
			name:    "Test empty keyword",
			input:   []string{""},
			wantErr: true,
		},
		{
			name:    "Test valid keywords",
			input:   []string{"hello", "world"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateKeywords(tt.input)

			if (got != nil && !tt.wantErr) || (got == nil && tt.wantErr) {
				t.Errorf("ValidateKeywords() error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func TestCustomDetectorsRegexValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]string
		wantErr bool
	}{
		{
			name: "Test list of keywords",
			input: map[string]string{
				"id_pat_example": "([a-zA-Z0-9]{32})",
			},
			wantErr: false,
		},
		{
			name:    "Test empty list of keywords",
			input:   map[string]string{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateRegex(tt.input)

			if (got != nil && !tt.wantErr) || (got == nil && tt.wantErr) {
				t.Errorf("ValidateRegex() error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func TestCustomDetectorsVerifyEndpointValidation(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		unsafe   bool
		wantErr  bool
	}{
		{
			name:     "Test http endpoint with unsafe flag",
			endpoint: "http://localhost:8000/{id_pat_example}",
			unsafe:   true,
			wantErr:  false,
		},
		{
			name:     "Test http endpoint without unsafe flag",
			endpoint: "http://localhost:8000/{id_pat_example}",
			unsafe:   false,
			wantErr:  true,
		},
		{
			name:     "Test https endpoint with unsafe flag",
			endpoint: "https://localhost:8000/{id_pat_example}",
			unsafe:   true,
			wantErr:  false,
		},
		{
			name:     "Test https endpoint without unsafe flag",
			endpoint: "https://localhost:8000/{id_pat_example}",
			unsafe:   false,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateVerifyEndpoint(tt.endpoint, tt.unsafe)

			if (got != nil && !tt.wantErr) || (got == nil && tt.wantErr) {
				t.Errorf("ValidateVerifyEndpoint() error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func TestCustomDetectorsVerifyHeadersValidation(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		wantErr bool
	}{
		{
			name:    "Test single header",
			headers: []string{"Authorization: Bearer {secret_pat_example.0}"},
			wantErr: false,
		},
		{
			name:    "Test invalid header",
			headers: []string{"Hello world"},
			wantErr: true,
		},
		{
			name:    "Test ugly header",
			headers: []string{"Hello:::::::world::hi:"},
			wantErr: false,
		},
		{
			name:    "Test empty header",
			headers: []string{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateVerifyHeaders(tt.headers)

			if (got != nil && !tt.wantErr) || (got == nil && tt.wantErr) {
				t.Errorf("ValidateVerifyHeaders() error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func TestCustomDetectorsVerifyRangeValidation(t *testing.T) {
	tests := []struct {
		name    string
		ranges  []string
		wantErr bool
	}{
		{
			name:    "Test multiple mixed ranges",
			ranges:  []string{"200", "300-350"},
			wantErr: false,
		},
		{
			name:    "Test invalid non-number range",
			ranges:  []string{"hi"},
			wantErr: true,
		},
		{
			name:    "Test invalid lower to upper range",
			ranges:  []string{"200-100"},
			wantErr: true,
		},
		{
			name:    "Test invalid http range",
			ranges:  []string{"400-1000"},
			wantErr: true,
		},
		{
			name:    "Test multiple ranges with invalid inputs",
			ranges:  []string{"322", "hello-world", "100-200"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateVerifyRanges(tt.ranges)

			if (got != nil && !tt.wantErr) || (got == nil && tt.wantErr) {
				t.Errorf("ValidateVerifyRanges() error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func TestCustomDetectorsVerifyRegexVarsValidation(t *testing.T) {
	tests := []struct {
		name    string
		regex   map[string]string
		body    string
		wantErr bool
	}{
		{
			name:    "Regex defined but not used in body",
			regex:   map[string]string{"id": "[0-9]{1,10}", "id_pat_example": "([a-zA-Z0-9]{32})"},
			body:    "hello world",
			wantErr: false,
		},
		{
			name:    "Regex defined and is used in body",
			regex:   map[string]string{"id": "[0-9]{1,10}", "id_pat_example": "([a-zA-Z0-9]{32})"},
			body:    "hello world {id}",
			wantErr: false,
		},
		{
			name:    "Regex var in body but not defined",
			regex:   map[string]string{"id": "[0-9]{1,10}", "id_pat_example": "([a-zA-Z0-9]{32})"},
			body:    "hello world {hello}",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateRegexVars(tt.regex, tt.body)

			if (got != nil && !tt.wantErr) || (got == nil && tt.wantErr) {
				t.Errorf("ValidateRegexVars() error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}
