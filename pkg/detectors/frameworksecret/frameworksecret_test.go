package frameworksecret

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// Valid test secrets for each framework - realistic entropy
	// Note: Avoid patterns that match TruffleHog's default false positive wordlist (abcde, etc.)
	validSymfonySecret = "f1e2d3c4b5a6978869574635241302f1"                                 // 32 hex chars, no "abcde" sequence
	validLaravelSecret = "base64:Kf5Lx9YmNwPq2RsTuVxWzQ3B4C5D6E7F8G9H0IjKlMn="              // base64 with prefix
	validDjangoSecret  = "django-insecure-x7k#m2$9p@q!w3e4r5t6y7u8i9o0-lsdfkjhg23847"       // 50+ chars
	validRailsSecret   = "f1e2d3c4b5a697886957463524130211f1e2d3c4b5a697886957463524130211" // 64 hex chars
)

func TestFrameworkSecretKey_Keywords(t *testing.T) {
	d := Scanner{}
	keywords := d.Keywords()

	expected := []string{"SECRET_KEY_BASE", "APP_SECRET", "APP_KEY", "SECRET_KEY"}

	if diff := cmp.Diff(expected, keywords); diff != "" {
		t.Errorf("Keywords() mismatch (-want +got):\n%s", diff)
	}
}

func TestFrameworkSecretKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "Symfony APP_SECRET basic",
			input: "APP_SECRET=" + validSymfonySecret,
			want:  []string{validSymfonySecret},
		},
		{
			name:  "Symfony APP_SECRET with double quotes",
			input: `APP_SECRET="` + validSymfonySecret + `"`,
			want:  []string{validSymfonySecret},
		},
		{
			name:  "Symfony APP_SECRET with single quotes",
			input: `APP_SECRET='` + validSymfonySecret + `'`,
			want:  []string{validSymfonySecret},
		},
		{
			name:  "Laravel APP_KEY basic",
			input: "APP_KEY=" + validLaravelSecret,
			want:  []string{validLaravelSecret},
		},
		{
			name:  "Laravel APP_KEY with quotes",
			input: `APP_KEY="` + validLaravelSecret + `"`,
			want:  []string{validLaravelSecret},
		},
		{
			name:  "Django SECRET_KEY single quotes",
			input: `SECRET_KEY='` + validDjangoSecret + `'`,
			want:  []string{validDjangoSecret},
		},
		{
			name:  "Django SECRET_KEY double quotes",
			input: `SECRET_KEY="` + validDjangoSecret + `"`,
			want:  []string{validDjangoSecret},
		},
		{
			name:  "Rails SECRET_KEY_BASE basic",
			input: "SECRET_KEY_BASE=" + validRailsSecret,
			want:  []string{validRailsSecret},
		},
		{
			name:  "Rails SECRET_KEY_BASE with colon (YAML)",
			input: "SECRET_KEY_BASE: " + validRailsSecret,
			want:  []string{validRailsSecret},
		},
		{
			name:  "Multiple secrets in one file",
			input: "APP_SECRET=" + validSymfonySecret + "\nAPP_KEY=" + validLaravelSecret,
			want:  []string{validSymfonySecret, validLaravelSecret},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by any pattern", d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
				for i, r := range results {
					t.Logf("  result[%d]: %s", i, string(r.Raw))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.Raw)] = struct{}{}
			}

			for _, w := range test.want {
				if _, ok := actual[w]; !ok {
					t.Errorf("expected to find secret %q in results", w)
				}
			}
		})
	}
}

func TestFrameworkSecretKey_FromData(t *testing.T) {
	ctx := context.Background()
	d := Scanner{}

	tests := []struct {
		name      string
		input     string
		wantFound bool
		framework string
	}{
		// Positive cases - should be detected
		{
			name:      "Symfony secret in .env file",
			input:     "# Application\nAPP_SECRET=" + validSymfonySecret + "\nAPP_ENV=prod",
			wantFound: true,
			framework: "Symfony",
		},
		{
			name:      "Laravel secret in .env file",
			input:     "APP_NAME=Laravel\nAPP_KEY=" + validLaravelSecret + "\nAPP_DEBUG=true",
			wantFound: true,
			framework: "Laravel",
		},
		{
			name:      "Django secret in settings.py",
			input:     "SECRET_KEY = '" + validDjangoSecret + "'",
			wantFound: true,
			framework: "Django",
		},
		{
			name:      "Rails secret in credentials",
			input:     "SECRET_KEY_BASE=" + validRailsSecret,
			wantFound: true,
			framework: "Rails",
		},

		// Negative cases - should NOT be detected
		{
			name:      "Too short Symfony secret",
			input:     "APP_SECRET=abc123",
			wantFound: false,
		},
		{
			name:      "Environment variable reference",
			input:     "APP_SECRET=${SYMFONY_SECRET}",
			wantFound: false,
		},
		{
			name:      "Laravel without base64 prefix",
			input:     "APP_KEY=notavalidlaravelkeybecauseithasnobase64prefix",
			wantFound: false,
		},
		{
			name:      "Django secret too short",
			input:     "SECRET_KEY='short'",
			wantFound: false,
		},
		{
			name:      "Django without quotes (ambiguous)",
			input:     "SECRET_KEY=noquotessoitcouldbeanyapplicationnotjustdjango",
			wantFound: false,
		},
		{
			name:      "Repeating characters",
			input:     "APP_SECRET=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantFound: false,
		},
		{
			name:      "Template syntax",
			input:     "APP_SECRET={{ symfony_secret }}",
			wantFound: false,
		},
		{
			name:      "Rails secret too short",
			input:     "SECRET_KEY_BASE=abc123",
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results, err := d.FromData(ctx, false, []byte(tc.input))
			if err != nil {
				t.Fatalf("FromData error: %v", err)
			}

			found := len(results) > 0
			if found != tc.wantFound {
				t.Errorf("FromData() found = %v, want %v", found, tc.wantFound)
				if found {
					t.Logf("Unexpected result: %s", string(results[0].Raw))
				}
			}

			if tc.wantFound && len(results) > 0 {
				if results[0].ExtraData["framework"] != tc.framework {
					t.Errorf("expected framework %q, got %q", tc.framework, results[0].ExtraData["framework"])
				}
			}
		})
	}
}

func TestFrameworkSecretKey_NoDuplicates(t *testing.T) {
	ctx := context.Background()
	d := Scanner{}

	// SECRET_KEY_BASE should NOT also match as SECRET_KEY
	input := "SECRET_KEY_BASE=" + validRailsSecret

	results, err := d.FromData(ctx, false, []byte(input))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected exactly 1 result, got %d", len(results))
		for i, r := range results {
			t.Logf("  result[%d]: framework=%s, secret=%s", i, r.ExtraData["framework"], string(r.Raw))
		}
	}

	if len(results) > 0 && results[0].ExtraData["framework"] != "Rails" {
		t.Errorf("expected framework 'Rails', got %q", results[0].ExtraData["framework"])
	}
}

func TestFrameworkSecretKey_Redaction(t *testing.T) {
	ctx := context.Background()
	d := Scanner{}

	input := "APP_SECRET=" + validSymfonySecret

	results, err := d.FromData(ctx, false, []byte(input))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	redacted := results[0].Redacted

	// Should start with first 8 chars
	if !startsWith(redacted, validSymfonySecret[:8]) {
		t.Errorf("redacted should start with first 8 chars, got: %s", redacted)
	}

	// Should end with last 4 chars
	if !endsWith(redacted, validSymfonySecret[len(validSymfonySecret)-4:]) {
		t.Errorf("redacted should end with last 4 chars, got: %s", redacted)
	}

	// Should contain asterisks
	if !contains(redacted, "****") {
		t.Errorf("redacted should contain asterisks, got: %s", redacted)
	}
}

func TestFrameworkSecretKey_Entropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
	}{
		{
			name:    "hex string has high entropy",
			input:   "a1b2c3d4e5f6789abcdef0123456789a",
			wantMin: 3.5,
		},
		{
			name:    "repeating chars has low entropy",
			input:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantMin: 0,
		},
		{
			name:    "base64 has high entropy",
			input:   "Kf5Lx9YmNwPq2RsTuVxWzA3B4C5D6E7F8G9H0IjKlMn=",
			wantMin: 4.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entropy := shannonEntropy(tc.input)
			if entropy < tc.wantMin {
				t.Errorf("entropy = %f, want >= %f", entropy, tc.wantMin)
			}
		})
	}
}

func TestFrameworkSecretKey_IsFalsePositive(t *testing.T) {
	d := Scanner{}

	tests := []struct {
		name   string
		secret string
		wantFP bool
	}{
		{
			name:   "Valid secret",
			secret: validSymfonySecret,
			wantFP: false,
		},
		{
			name:   "Example keyword",
			secret: "example1234567890abcdef1234567890",
			wantFP: true,
		},
		{
			name:   "Sample keyword",
			secret: "sample_1234567890abcdef1234567890",
			wantFP: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := detectors.Result{
				Raw: []byte(tc.secret),
			}

			isFP, _ := d.IsFalsePositive(result)
			if isFP != tc.wantFP {
				t.Errorf("IsFalsePositive() = %v, want %v", isFP, tc.wantFP)
			}
		})
	}
}

func TestFrameworkSecretKey_Description(t *testing.T) {
	d := Scanner{}
	desc := d.Description()

	if desc == "" {
		t.Error("Description() should not be empty")
	}

	// Check that it mentions security impact
	if !contains(desc, "session") || !contains(desc, "CSRF") {
		t.Error("Description should mention security impact (sessions, CSRF)")
	}
}

// Helper functions
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
