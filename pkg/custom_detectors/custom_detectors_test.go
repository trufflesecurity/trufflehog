package custom_detectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
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

func TestCustomRegexTemplateParsingWithRotatedRanges(t *testing.T) {
	testYaml := `name: test
keywords:
- secret
regex:
  token: ([a-zA-Z0-9]{32})
verify:
- endpoint: http://localhost:8000/
  unsafe: true
  headers:
  - 'Authorization: Bearer token'
  successRanges:
  - '200'
  rotatedRanges:
  - '401'
  - 403-404`

	var got custom_detectorspb.CustomRegex
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testYaml), &got))
	assert.Equal(t, 1, len(got.Verify))
	assert.Equal(t, []string{"200"}, got.Verify[0].SuccessRanges)
	assert.Equal(t, []string{"401", "403-404"}, got.Verify[0].RotatedRanges)
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

func TestFromData_InvalidRegEx(t *testing.T) {
	c := &CustomRegexWebhook{
		CustomRegex: &custom_detectorspb.CustomRegex{
			Name:     "Internal bi tool",
			Keywords: []string{"secret_v1_", "pat_v2_"},
			Regex: map[string]string{
				"test": "!!?(?:?)[a-zA-Z0-9]{32}", // invalid regex
			},
		},
	}

	_, err := c.FromData(context.Background(), false, []byte("test"))
	assert.Error(t, err)
}

func TestProductIndices(t *testing.T) {
	tests := []struct {
		name  string
		input []int
		want  [][]int
	}{
		{
			name:  "zero",
			input: []int{3, 0},
			want:  nil,
		},
		{
			name:  "one input",
			input: []int{3},
			want:  [][]int{{0}, {1}, {2}},
		},
		{
			name:  "two inputs",
			input: []int{3, 2},
			want: [][]int{
				{0, 0}, {1, 0}, {2, 0},
				{0, 1}, {1, 1}, {2, 1},
			},
		},
		{
			name:  "three inputs",
			input: []int{3, 2, 3},
			want: [][]int{
				{0, 0, 0}, {1, 0, 0}, {2, 0, 0},
				{0, 1, 0}, {1, 1, 0}, {2, 1, 0},
				{0, 0, 1}, {1, 0, 1}, {2, 0, 1},
				{0, 1, 1}, {1, 1, 1}, {2, 1, 1},
				{0, 0, 2}, {1, 0, 2}, {2, 0, 2},
				{0, 1, 2}, {1, 1, 2}, {2, 1, 2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := productIndices(tt.input...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProductIndicesMax(t *testing.T) {
	got := productIndices(2, 3, 4, 5, 6)
	assert.GreaterOrEqual(t, 2*3*4*5*6, maxTotalMatches)
	assert.Equal(t, maxTotalMatches, len(got))
}

func TestPermutateMatches(t *testing.T) {
	tests := []struct {
		name  string
		input map[string][][]string
		want  []map[string][]string
	}{
		{
			name:  "two matches",
			input: map[string][][]string{"foo": {{"matchA"}, {"matchB"}}, "bar": {{"matchC"}}},
			want: []map[string][]string{
				{"foo": {"matchA"}, "bar": {"matchC"}},
				{"foo": {"matchB"}, "bar": {"matchC"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := permutateMatches(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDetector(t *testing.T) {
	detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name: "test",
		// "password" is normally flagged as a false positive, but CustomRegex
		// should allow the user to decide and report it as a result.
		Keywords: []string{"password"},
		Regex:    map[string]string{"regex": "password=\"(.*)\""},
	})
	assert.NoError(t, err)
	results, err := detector.FromData(context.Background(), false, []byte(`password="123456"`))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	assert.Equal(t, results[0].Raw, []byte(`123456`))
}

func TestDetectorPrimarySecret(t *testing.T) {
	detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:             "test",
		Keywords:         []string{"secret"},
		Regex:            map[string]string{"id": "id_[A-Z0-9]{10}_yy", "secret": "secret_[A-Z0-9]{10}_yy"},
		PrimaryRegexName: "secret",
	})
	assert.NoError(t, err)
	results, err := detector.FromData(context.Background(), false, []byte(`
	// getData returns id and secret
	func getData()(string, string){
    	return "id_ALPHA10100_yy", "secret_YI7C90ACY1_yy"
	}
	`))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	assert.Equal(t, "secret_YI7C90ACY1_yy", results[0].GetPrimarySecretValue())
}

func TestDetectorPrimarySecretFullMatch(t *testing.T) {
	tests := []struct {
		name  string
		input *custom_detectorspb.CustomRegex
		chunk []byte
		want  string
	}{
		{
			name: "primary regex full match",
			input: &custom_detectorspb.CustomRegex{
				Name:             "test",
				Keywords:         []string{"secret"},
				Regex:            map[string]string{"secret": `secret *= *"([^"\r\n]+)"`},
				PrimaryRegexName: "secret",
			},
			chunk: []byte(`
			// some code
			secret="mysecret"
			// some code
			`),
			want: `secret="mysecret"`,
		},
		{
			name: "primary regex full match multiline",
			input: &custom_detectorspb.CustomRegex{
				Name:             "test",
				Keywords:         []string{"secret"},
				Regex:            map[string]string{"secret": `secret *= *"([^"]+)"`},
				PrimaryRegexName: "secret",
			},
			chunk: []byte(`
			// some code
			secret="mysecret
			thatspansmultiplelines"
			// some code
			`),
			want: `secret="mysecret
			thatspansmultiplelines"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewWebhookCustomRegex(tt.input)
			assert.NoError(t, err)
			results, err := detector.FromData(context.Background(), false, tt.chunk)
			assert.NoError(t, err)
			assert.Equal(t, 1, len(results))
			assert.Equal(t, tt.want, results[0].GetPrimarySecretValue())
		})
	}

}

func TestDetectorValidations(t *testing.T) {
	type args struct {
		CustomRegex *custom_detectorspb.CustomRegex
		Data        string
	}

	tests := []struct {
		name  string
		input args
		want  []detectors.Result
	}{
		{
			name: "custom validation - contains digit",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsDigit: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStr0ngP@ssword!
						End of file`,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CustomRegex,
					DetectorName: "test",
					Verified:     false,
					Raw:          []byte("MyStr0ngP@ssword!"),
				},
			},
		},
		{
			name: "custom validation - does not contains digit",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsDigit: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStrongPassword!
						End of file`,
			},
			want: nil,
		},
		{
			name: "custom validation - contains lowercase",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsLowercase: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStrongPassword!
						End of file`,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CustomRegex,
					DetectorName: "test",
					Verified:     false,
					Raw:          []byte("MyStrongPassword!"),
				},
			},
		},
		{
			name: "custom validation - does not contains lowercase",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsLowercase: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MYSTRONGPASSWORD!
						End of file`,
			},
			want: nil,
		},
		{
			name: "custom validation - contains uppercase",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsUppercase: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStrongPassword!
						End of file`,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CustomRegex,
					DetectorName: "test",
					Verified:     false,
					Raw:          []byte("MyStrongPassword!"),
				},
			},
		},
		{
			name: "custom validation - does not contains uppercase",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsUppercase: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: mystrongpassword!
						End of file`,
			},
			want: nil,
		},
		{
			name: "custom validation - contains special character",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsSpecialChar: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStr@ngP@ssword!
						End of file`,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CustomRegex,
					DetectorName: "test",
					Verified:     false,
					Raw:          []byte("MyStr@ngP@ssword!"),
				},
			},
		},
		{
			name: "custom validation - does not contains special character",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsSpecialChar: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStrongPassword
						End of file`,
			},
			want: nil,
		},
		{
			name: "custom validation - contains uppercase and special characters",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsUppercase:   true,
							ContainsSpecialChar: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStrongP@ssword
						End of file`,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CustomRegex,
					DetectorName: "test",
					Verified:     false,
					Raw:          []byte("MyStrongP@ssword"),
				},
			},
		},
		{
			name: "custom validation - contains uppercase but does not contain special characters",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsUppercase:   true,
							ContainsSpecialChar: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStrongPassword
						End of file`,
			},
			want: nil,
		},
		{
			name: "custom validation - wrong regex name in validations",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password"},
					Regex:    map[string]string{"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"wrong": {
							ContainsUppercase: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: mystrongp@ssword
						End of file`,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CustomRegex,
					DetectorName: "test",
					Verified:     false,
					Raw:          []byte("mystrongp@ssword"),
				},
			},
		},
		{
			name: "custom validation - multiple regex validations",
			input: args{
				CustomRegex: &custom_detectorspb.CustomRegex{
					Name:     "test",
					Keywords: []string{"password", "api_key"},
					Regex: map[string]string{
						"password": `([A-Za-z0-9!@#$%^&*()_+=\-]{12,})`,
						"api_key":  `([a-f0-9_-]{32})`,
					},
					Validations: map[string]*custom_detectorspb.ValidationConfig{
						"password": {
							ContainsUppercase:   true,
							ContainsSpecialChar: true,
						},
						"api_key": {
							ContainsSpecialChar: true,
						},
					},
				},
				Data: `This is custom example
						This file has a random text and maybe a secret
						Password: MyStrongP@ssword
						API_Key: c392c9837d69b44c764cbf260b-e6184 // should be detected
						API_Key: c392c9837d69b44c764cbf260be6184 // should be filtered by validation
						End of file`,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CustomRegex,
					DetectorName: "test",
					Verified:     false,
					Raw:          []byte("c392c9837d69b44c764cbf260b-e6184MyStrongP@ssword"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewWebhookCustomRegex(tt.input.CustomRegex)
			assert.NoError(t, err)
			results, err := detector.FromData(context.Background(), false, []byte(tt.input.Data))
			assert.NoError(t, err)

			ignoreOpts := cmp.Options{
				cmpopts.IgnoreUnexported(detectors.Result{}),
				cmpopts.IgnoreFields(detectors.Result{}, "ExtraData"),
			}
			if diff := cmp.Diff(results, tt.want, ignoreOpts); diff != "" {
				t.Errorf("CustomDetector.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestNewWebhookCustomRegex_Validation(t *testing.T) {
	t.Parallel()

	// A known-good baseline; each test case mutates exactly one thing to trigger a specific validator.
	base := func() *custom_detectorspb.CustomRegex {
		return &custom_detectorspb.CustomRegex{
			Name:     "ok",
			Keywords: []string{"kw"},
			Regex: map[string]string{
				"main": `\btoken_[a-z]+\b`,
			},
			PrimaryRegexName: "main",
			ExcludeRegexesCapture: []string{
				`^skip_.*$`,
			},
			ExcludeRegexesMatch: []string{
				`^ignore_.*$`,
			},
			Verify: []*custom_detectorspb.VerifierConfig{
				{
					Endpoint: "https://example.com/verify",
					Unsafe:   false,
					Headers:  []string{"Authorization: Bearer x"},
				},
			},
		}
	}

	tests := []struct {
		name          string
		mutate        func(*custom_detectorspb.CustomRegex)
		wantErr       bool
		wantErrSubstr string // substring expected in error
	}{
		{
			name:   "Validate everything ok",
			mutate: func(pb *custom_detectorspb.CustomRegex) {},
		},
		{
			name: "ValidateKeywords: no keywords",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Keywords = nil
			},
			wantErr:       true,
			wantErrSubstr: "no keywords",
		},
		{
			name: "ValidateKeywords: empty keyword",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Keywords = []string{""}
			},
			wantErr:       true,
			wantErrSubstr: "empty keyword",
		},
		{
			name: "ValidateRegex: no regex",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Regex = nil
			},
			wantErr:       true,
			wantErrSubstr: "no regex",
		},
		{
			name: "ValidateRegex: invalid regex in map",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Regex = map[string]string{"main": "("} // invalid
			},
			wantErr:       true,
			wantErrSubstr: "regex 'main':",
		},
		{
			name: "ValidateRegexSlice: invalid exclude_regexes_capture",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.ExcludeRegexesCapture = []string{"("} // invalid
			},
			wantErr:       true,
			wantErrSubstr: "regex '1':",
		},
		{
			name: "ValidateRegexSlice: invalid exclude_regexes_match",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.ExcludeRegexesMatch = []string{"("} // invalid
			},
			wantErr:       true,
			wantErrSubstr: "regex '1':",
		},
		{
			name: "ValidatePrimaryRegexName: unknown primary regex name",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.PrimaryRegexName = "does-not-exist"
			},
			wantErr:       true,
			wantErrSubstr: `unknown primary regex name: "does-not-exist"`,
		},
		{
			name: "ValidateVerifyEndpoint: empty endpoint",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Verify = []*custom_detectorspb.VerifierConfig{
					{Endpoint: "", Unsafe: false, Headers: []string{"A: b"}},
				}
			},
			wantErr:       true,
			wantErrSubstr: "no endpoint",
		},
		{
			name: "ValidateVerifyEndpoint: http endpoint without unsafe=true",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Verify = []*custom_detectorspb.VerifierConfig{
					{Endpoint: "http://example.com/verify", Unsafe: false, Headers: []string{"A: b"}},
				}
			},
			wantErr:       true,
			wantErrSubstr: "http endpoint must have unsafe=true",
		},
		{
			name: "ValidateVerifyHeaders: header missing colon",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Verify = []*custom_detectorspb.VerifierConfig{
					{Endpoint: "https://example.com/verify", Unsafe: false, Headers: []string{"Authorization Bearer x"}},
				}
			},
			wantErr:       true,
			wantErrSubstr: `must contain a colon`,
		},
		{
			name: "ValidateVerifyRanges: invalid successRanges",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Verify = []*custom_detectorspb.VerifierConfig{
					{Endpoint: "https://example.com/verify", Headers: []string{"A: b"}, SuccessRanges: []string{"abc"}},
				}
			},
			wantErr:       true,
			wantErrSubstr: "unable to convert http code to int",
		},
		{
			name: "ValidateVerifyRanges: invalid rotatedRanges",
			mutate: func(pb *custom_detectorspb.CustomRegex) {
				pb.Verify = []*custom_detectorspb.VerifierConfig{
					{Endpoint: "https://example.com/verify", Headers: []string{"A: b"}, RotatedRanges: []string{"999"}},
				}
			},
			wantErr:       true,
			wantErrSubstr: "invalid http status code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pb := base()
			tt.mutate(pb)

			got, err := NewWebhookCustomRegex(pb)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error=%v, got error=%v (result=%#v)", tt.wantErr, err != nil, got)
			}
			if tt.wantErr && got != nil {
				t.Fatalf("expected nil result on error, got=%#v", got)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Fatalf("error mismatch:\n  got:  %q\n  want substring: %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}

func TestNewWebhookCustomRegex_EnsurePrimaryRegexNameSet(t *testing.T) {
	t.Parallel()

	pb := &custom_detectorspb.CustomRegex{
		Name:     "test",
		Keywords: []string{"kw"},
		Regex: map[string]string{
			"regex_a": `regex_a`,
			"regex_b": `regex_b`,
		},
		// PrimaryRegexName is not set.
	}

	detector, err := NewWebhookCustomRegex(pb)
	assert.NoError(t, err)
	assert.Equal(t, "regex_a", detector.GetPrimaryRegexName(), "expected PrimaryRegexName to be set to regex_a")
}

func TestVerificationWithConfigurableRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		serverStatus  int
		successRanges []string
		rotatedRanges []string
		wantVerified  bool
		wantVerifyErr bool
	}{
		{
			name:          "backward compat: no ranges, 200 -> verified",
			serverStatus:  200,
			wantVerified:  true,
			wantVerifyErr: false,
		},
		{
			name:          "backward compat: no ranges, 401 -> unverified",
			serverStatus:  401,
			wantVerified:  false,
			wantVerifyErr: false,
		},
		{
			name:          "successRanges match -> verified",
			serverStatus:  201,
			successRanges: []string{"200-202"},
			wantVerified:  true,
			wantVerifyErr: false,
		},
		{
			name:          "rotatedRanges match -> not verified, no error",
			serverStatus:  401,
			successRanges: []string{"200"},
			rotatedRanges: []string{"401", "403"},
			wantVerified:  false,
			wantVerifyErr: false,
		},
		{
			name:          "neither match -> not verified, verification error",
			serverStatus:  500,
			successRanges: []string{"200"},
			rotatedRanges: []string{"401"},
			wantVerified:  false,
			wantVerifyErr: true,
		},
		{
			name:          "successRanges range boundary inclusive",
			serverStatus:  250,
			successRanges: []string{"200-250"},
			wantVerified:  true,
			wantVerifyErr: false,
		},
		{
			name:          "only successRanges: non-match means rotated",
			serverStatus:  401,
			successRanges: []string{"200"},
			wantVerified:  false,
			wantVerifyErr: false,
		},
		{
			name:          "only rotatedRanges: non-match means live",
			serverStatus:  200,
			rotatedRanges: []string{"401", "403"},
			wantVerified:  true,
			wantVerifyErr: false,
		},
		{
			name:          "only rotatedRanges: match means rotated",
			serverStatus:  401,
			rotatedRanges: []string{"401"},
			wantVerified:  false,
			wantVerifyErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}))
			defer ts.Close()

			detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
				Name:     "test",
				Keywords: []string{"secret"},
				Regex:    map[string]string{"token": `(secret_[a-zA-Z0-9]{10})`},
				Verify: []*custom_detectorspb.VerifierConfig{
					{
						Endpoint:      ts.URL,
						Unsafe:        true,
						Headers:       []string{"Authorization: Bearer test"},
						SuccessRanges: tt.successRanges,
						RotatedRanges: tt.rotatedRanges,
					},
				},
			})
			assert.NoError(t, err)

			results, err := detector.FromData(context.Background(), true, []byte("secret_ABCDEFGHIJ"))
			assert.NoError(t, err)
			assert.Equal(t, 1, len(results), "expected exactly one result")

			result := results[0]
			assert.Equal(t, tt.wantVerified, result.Verified, "Verified mismatch")
			if tt.wantVerifyErr {
				assert.NotNil(t, result.VerificationError(), "expected a verification error")
			} else {
				assert.Nil(t, result.VerificationError(), "expected no verification error")
			}
		})
	}
}

func TestVerificationMixedRangedAndLegacyVerifiers(t *testing.T) {
	t.Parallel()

	// Verifier 1 has ranges configured but returns a status matching neither.
	// Verifier 2 is legacy (no ranges) and returns 200.
	// The result should be Verified=true with NO verification error.
	tsRanged := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer tsRanged.Close()

	tsLegacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer tsLegacy.Close()

	detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "test",
		Keywords: []string{"secret"},
		Regex:    map[string]string{"token": `(secret_[a-zA-Z0-9]{10})`},
		Verify: []*custom_detectorspb.VerifierConfig{
			{
				Endpoint:      tsRanged.URL,
				Unsafe:        true,
				Headers:       []string{"A: b"},
				SuccessRanges: []string{"200"},
				RotatedRanges: []string{"401"},
			},
			{
				Endpoint: tsLegacy.URL,
				Unsafe:   true,
				Headers:  []string{"A: b"},
			},
		},
	})
	assert.NoError(t, err)

	results, err := detector.FromData(context.Background(), true, []byte("secret_ABCDEFGHIJ"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	assert.True(t, results[0].Verified, "expected Verified=true from legacy fallback")
	assert.Nil(t, results[0].VerificationError(), "legacy success must not produce a spurious verification error")
}

func BenchmarkProductIndices(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = productIndices(3, 2, 6)
	}
}

// ─── OAuth2 token source construction ────────────────────────────────

func TestBuildTokenSource_NilAuth(t *testing.T) {
	t.Parallel()
	ts, err := BuildTokenSource(nil)
	assert.NoError(t, err)
	assert.Nil(t, ts)
}

func TestBuildTokenSource_UnknownAuthType(t *testing.T) {
	t.Parallel()
	// Empty VerifierAuth has no oneof set; BuildTokenSource should
	// return an error.
	auth := &custom_detectorspb.VerifierAuth{}
	ts, err := BuildTokenSource(auth)
	assert.Error(t, err)
	assert.Nil(t, ts)
	assert.Contains(t, err.Error(), "unrecognized auth config type")
}

func TestBuildTokenSource_ROPC(t *testing.T) {
	t.Parallel()
	auth := &custom_detectorspb.VerifierAuth{
		AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
			Oauth2: &custom_detectorspb.OAuth2Config{
				TokenEndpoint: "https://idp.example.com/token",
				GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{
					Ropc: &custom_detectorspb.ROPCConfig{
						Username:     "user",
						Password:     "pass",
						ClientId:     "client",
						ClientSecret: "secret",
						Scope:        "read write",
					},
				},
			},
		},
	}
	ts, err := BuildTokenSource(auth)
	assert.NoError(t, err)
	assert.NotNil(t, ts, "expected a non-nil token source for valid ROPC config")

	// The returned value should be a TracedTokenSource with a non-empty trace.
	traced, ok := ts.(*detectors.TracedTokenSource)
	assert.True(t, ok, "expected *detectors.TracedTokenSource, got %T", ts)
	assert.NotEmpty(t, traced.Trace, "trace ID should be set")
}

func TestROPCTokenSource_DefaultExpiryWhenIdPOmitsIt(t *testing.T) {
	t.Parallel()

	// Simulate an IdP that returns a token without expires_in.
	// The ropcTokenSource should set a default expiry so
	// ReuseTokenSource doesn't cache it forever.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Token response with no expires_in field.
		_, _ = fmt.Fprint(w, `{"access_token":"tok123","token_type":"Bearer"}`)
	}))
	defer srv.Close()

	auth := &custom_detectorspb.VerifierAuth{
		AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
			Oauth2: &custom_detectorspb.OAuth2Config{
				TokenEndpoint: srv.URL,
				GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{
					Ropc: &custom_detectorspb.ROPCConfig{
						Username:     "user",
						Password:     "pass",
						ClientId:     "c",
						ClientSecret: "s",
					},
				},
			},
		},
	}
	ts, err := BuildTokenSource(auth)
	require.NoError(t, err)

	tok, err := ts.Token()
	require.NoError(t, err)
	assert.Equal(t, "tok123", tok.AccessToken)
	assert.False(t, tok.Expiry.IsZero(), "expiry should be set even when IdP omits expires_in")
	assert.WithinDuration(t, time.Now().Add(defaultTokenLifetime), tok.Expiry, 30*time.Second)
}

// ─── Auth validation in NewWebhookCustomRegex ────────────────────────

func TestNewWebhookCustomRegex_RejectsUnusableAuth(t *testing.T) {
	t.Parallel()

	// Auth is set but has no grant config, so BuildTokenSource returns nil.
	// NewWebhookCustomRegex should reject this at init rather than silently
	// falling back to unauthenticated verification.
	pb := &custom_detectorspb.CustomRegex{
		Name:     "test",
		Keywords: []string{"secret"},
		Regex:    map[string]string{"token": `(secret_[a-z]+)`},
		Verify: []*custom_detectorspb.VerifierConfig{
			{
				Endpoint: "https://verify.example.com/check",
				Headers:  []string{"Authorization: Bearer x"},
				Auth: &custom_detectorspb.VerifierAuth{
					AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
						Oauth2: &custom_detectorspb.OAuth2Config{
							TokenEndpoint: "https://idp.example.com/token",
							// No grant_config set — simulates unknown or missing grant type.
						},
					},
				},
			},
		},
	}

	_, err := NewWebhookCustomRegex(pb)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized OAuth2 grant type")
}

// ─── Token endpoint validation in NewWebhookCustomRegex ──────────────

func TestNewWebhookCustomRegex_RejectsHTTPTokenEndpoint(t *testing.T) {
	t.Parallel()

	pb := &custom_detectorspb.CustomRegex{
		Name:     "test",
		Keywords: []string{"secret"},
		Regex:    map[string]string{"token": `(secret_[a-z]+)`},
		Verify: []*custom_detectorspb.VerifierConfig{
			{
				// HTTPS verify endpoint is fine, but HTTP token
				// endpoint must fail without unsafe=true.
				Endpoint: "https://verify.example.com/check",
				Headers:  []string{"Authorization: Bearer x"},
				Auth: &custom_detectorspb.VerifierAuth{
					AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
						Oauth2: &custom_detectorspb.OAuth2Config{
							TokenEndpoint: "http://idp.example.com/token",
							GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{
								Ropc: &custom_detectorspb.ROPCConfig{
									Username: "u",
									Password: "p",
									ClientId: "c",
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := NewWebhookCustomRegex(pb)
	assert.Error(t, err, "expected error for HTTP token endpoint without unsafe=true")
	assert.Contains(t, err.Error(), "auth token endpoint")
}

func TestNewWebhookCustomRegex_AllowsHTTPTokenEndpointWithUnsafe(t *testing.T) {
	t.Parallel()

	pb := &custom_detectorspb.CustomRegex{
		Name:     "test",
		Keywords: []string{"secret"},
		Regex:    map[string]string{"token": `(secret_[a-z]+)`},
		Verify: []*custom_detectorspb.VerifierConfig{
			{
				Endpoint: "http://verify.example.com/check",
				Unsafe:   true,
				Headers:  []string{"Authorization: Bearer x"},
				Auth: &custom_detectorspb.VerifierAuth{
					AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
						Oauth2: &custom_detectorspb.OAuth2Config{
							TokenEndpoint: "http://idp.example.com/token",
							GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{
								Ropc: &custom_detectorspb.ROPCConfig{
									Username: "u",
									Password: "p",
									ClientId: "c",
								},
							},
						},
					},
				},
			},
		},
	}

	det, err := NewWebhookCustomRegex(pb)
	assert.NoError(t, err, "HTTP token endpoint should be allowed when unsafe=true")
	assert.NotNil(t, det)
}

// ─── Inline OAuth2 verification ──────────────────────────────────────

func TestInlineVerification_WithOAuth2(t *testing.T) {
	t.Parallel()

	// Stand up a fake verify server that requires a Bearer token and
	// returns verified=true when the token is present.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "oauth-test",
		Keywords: []string{"secret"},
		Regex:    map[string]string{"token": `(secret_[a-zA-Z0-9]{10})`},
		Verify: []*custom_detectorspb.VerifierConfig{
			{
				Endpoint: srv.URL,
				Unsafe:   true,
				Headers:  []string{"Content-Type: application/json"},
				Auth: &custom_detectorspb.VerifierAuth{
					AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
						Oauth2: &custom_detectorspb.OAuth2Config{
							// Token endpoint won't be called because we
							// verify that the OAuth2 client is constructed
							// and the Bearer header is added. The ROPC
							// token exchange would fail, so we rely on
							// the test below (without auth) to confirm
							// the inline plumbing works for non-OAuth2.
							// This test confirms the verifier struct has
							// a non-nil token source after init.
							TokenEndpoint: "https://idp.example.com/token",
							GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{
								Ropc: &custom_detectorspb.ROPCConfig{
									Username: "u",
									Password: "p",
									ClientId: "c",
								},
							},
						},
					},
				},
			},
		},
	})
	assert.NoError(t, err)

	// Verify the verifier has a token source configured.
	assert.Len(t, detector.verifiers, 1)
	assert.NotNil(t, detector.verifiers[0].tokenSource,
		"expected token source to be set on verifier")

	_, ok := detector.verifiers[0].tokenSource.(*detectors.TracedTokenSource)
	assert.True(t, ok, "expected *detectors.TracedTokenSource")
}

func TestInlineVerification_WithoutAuth(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "no-auth-test",
		Keywords: []string{"secret"},
		Regex:    map[string]string{"token": `(secret_[a-zA-Z0-9]{10})`},
		Verify: []*custom_detectorspb.VerifierConfig{
			{
				Endpoint: srv.URL,
				Unsafe:   true,
				Headers:  []string{"Content-Type: application/json"},
				// No auth block.
			},
		},
	})
	assert.NoError(t, err)

	// Verify no token source when auth isn't configured.
	assert.Len(t, detector.verifiers, 1)
	assert.Nil(t, detector.verifiers[0].tokenSource)

	// Verify the detector still works for inline verification without OAuth2.
	results, err := detector.FromData(context.Background(), true, []byte("secret_ABCDEFGHIJ"))
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.True(t, results[0].Verified)
}

// ─── YAML parsing for auth block ─────────────────────────────────────

func TestCustomRegexYAML_WithOAuth2Auth(t *testing.T) {
	t.Parallel()

	yaml := `name: oauth-detector
keywords:
- secret
regex:
  token: (secret_[a-z]+)
verify:
- endpoint: https://verify.example.com/check
  headers:
  - 'Authorization: Bearer {token.0}'
  auth:
    oauth2:
      token_endpoint: https://idp.example.com/oauth/token
      ropc:
        username: scanner
        password: hunter2
        client_id: my-client
        client_secret: my-secret
        scope: read write`

	var got custom_detectorspb.CustomRegex
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(yaml), &got))
	assert.Equal(t, 1, len(got.Verify))

	auth := got.Verify[0].GetAuth()
	assert.NotNil(t, auth)

	oc := auth.GetOauth2()
	assert.NotNil(t, oc)
	assert.Equal(t, "https://idp.example.com/oauth/token", oc.GetTokenEndpoint())

	ropc := oc.GetRopc()
	assert.NotNil(t, ropc)
	assert.Equal(t, "scanner", ropc.GetUsername())
	assert.Equal(t, "hunter2", ropc.GetPassword())
	assert.Equal(t, "my-client", ropc.GetClientId())
	assert.Equal(t, "my-secret", ropc.GetClientSecret())
	assert.Equal(t, "read write", ropc.GetScope())
}

// ─── Request body template ───────────────────────────────────────────

func TestValidateRequestBody_KnownTokens(t *testing.T) {
	t.Parallel()
	body := map[string]string{
		"credential":  "$secret",
		"source":      "$detector_type",
		"name":        "$detector_name",
		"auth":        "$token",
		"environment": "production",
	}
	assert.NoError(t, validateRequestBody(body))
}

func TestValidateRequestBody_UnknownToken(t *testing.T) {
	t.Parallel()
	body := map[string]string{
		"credential": "$secret",
		"unknown":    "$foo",
	}
	err := validateRequestBody(body)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "$foo")
	assert.Contains(t, err.Error(), "unknown")
}

func TestResolveRequestBody_Substitution(t *testing.T) {
	t.Parallel()
	template := map[string]string{
		"credential":  "$secret",
		"source":      "$detector_type",
		"environment": "production",
	}
	vars := map[string]string{
		"$secret":        "my-secret-value",
		"$detector_type": "CustomRegex",
		"$detector_name": "TestDetector",
	}
	body, err := ResolveRequestBody(template, vars)
	require.NoError(t, err)

	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, "my-secret-value", parsed["credential"])
	assert.Equal(t, "CustomRegex", parsed["source"])
	assert.Equal(t, "production", parsed["environment"])
}

func TestResolveRequestBody_TokenVar(t *testing.T) {
	t.Parallel()
	template := map[string]string{
		"cred":       "$secret",
		"auth_token": "$token",
	}
	vars := map[string]string{
		"$secret": "the-secret",
		"$token":  "jwt-token-value",
	}
	body, err := ResolveRequestBody(template, vars)
	require.NoError(t, err)

	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, "the-secret", parsed["cred"])
	assert.Equal(t, "jwt-token-value", parsed["auth_token"])
}

func TestNewWebhookCustomRegex_RejectsUnknownBodyToken(t *testing.T) {
	t.Parallel()
	pb := &custom_detectorspb.CustomRegex{
		Name:     "test-detector",
		Keywords: []string{"secret"},
		Regex:    map[string]string{"secret": `(secret_[a-z]+)`},
		Verify: []*custom_detectorspb.VerifierConfig{{
			Endpoint: "https://verify.example.com/check",
			Request: &custom_detectorspb.VerifyRequestBody{
				Body: map[string]string{
					"credential": "$secret",
					"bad_field":  "$nonexistent",
				},
			},
		}},
	}
	_, err := NewWebhookCustomRegex(pb)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "$nonexistent")
}
