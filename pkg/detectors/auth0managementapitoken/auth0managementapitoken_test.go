package auth0managementapitoken

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// TODO(kashif): Refactor the fake token generation if possible
	validPattern   = generateRandomString() // this has the exact token string only which can be used in want too
	validDomain    = "QHHPu7VPj.sI.auth0.com"
	invalidPattern = `
		auth0_credentials:
			apiToken: eywT2nGMZwOcbsUVBwfiRPEl8P_wnmo6XfdUoGVwxDfOSjNyqhYqFdi.KojZZOM8Ox
			domain: QHHPu7VPj.sI.auth0.com
	`
)

func TestAuth0ManagementApitToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: makeFakeTokenString(validPattern, validDomain),
			want:  []string{validPattern + validDomain},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

// makeFakeTokenString take a string token as parameter and make a string that looks like a token for testing
func makeFakeTokenString(token, domain string) string {
	return fmt.Sprintf("auth0:\n apiToken: %s \n domain: %s", token, domain)
}

// generateRandomString generates exactly 2001 char string for a fake token to by pass the check in detector for testing
func generateRandomString() string {
	const length = 2001
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	const charsetWithBoundaryChars = charset + ".-"

	random := rand.New(rand.NewSource(time.Now().UnixNano()))

	var builder strings.Builder
	builder.Grow(length)

	for i := 0; i < length-1; i++ {
		randomChar := charsetWithBoundaryChars[random.Intn(len(charset))]
		builder.WriteByte(randomChar)
	}

	// ensure last character is not boundary character
	lastChar := charset[random.Intn(len(charset))]
	builder.WriteByte(lastChar)

	// append ey in start as the token must start with 'ey'
	return fmt.Sprintf("ey%s", builder.String())
}
