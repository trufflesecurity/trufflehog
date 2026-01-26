package custom_detectors

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
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

func TestFromData_InvalidRegEx(t *testing.T) {
	c := &CustomRegexWebhook{
		&custom_detectorspb.CustomRegex{
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
	detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:             "test",
		Keywords:         []string{"secret"},
		Regex:            map[string]string{"secret": `secret *= *"([^"\r\n]+)"`},
		PrimaryRegexName: "secret",
	})

	assert.NoError(t, err)
	results, err := detector.FromData(context.Background(), false, []byte(`
	// some code
	secret="$existing_secret"
	// some code
	`))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	assert.Equal(t, `secret="$existing_secret"`, results[0].GetPrimarySecretValue())
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
					DetectorType: detectorspb.DetectorType_CustomRegex,
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
					DetectorType: detectorspb.DetectorType_CustomRegex,
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
					DetectorType: detectorspb.DetectorType_CustomRegex,
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
					DetectorType: detectorspb.DetectorType_CustomRegex,
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
					DetectorType: detectorspb.DetectorType_CustomRegex,
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
					DetectorType: detectorspb.DetectorType_CustomRegex,
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
					DetectorType: detectorspb.DetectorType_CustomRegex,
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

			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "ExtraData", "verificationError", "primarySecret")
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
			"first":  `first_regex`,
			"second": `second_regex`,
		},
		// PrimaryRegexName is not set.
	}

	detector, err := NewWebhookCustomRegex(pb)
	assert.NoError(t, err)
	assert.Equal(t, "first", detector.GetPrimaryRegexName(), "expected PrimaryRegexName to be set to the first regex name")
}

func BenchmarkProductIndices(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = productIndices(3, 2, 6)
	}
}
