package hashicorpvaultauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validRoleId     = "12345678-1234-1234-1234-123456789abc" // lowercase hex UUID
	validSecretId   = "87654321-4321-4321-4321-CBA987654321" // mixed case hex UUID
	validVaultUrl   = "https://my-org.hashicorp.cloud"
	invalidRoleId   = "12345678-1234-1234-1234-123456789abg" // invalid character 'g'
	invalidSecretId = "87654321-4321-4321-4321-CBA98765432G" // invalid character 'G'
	keyword         = "vault"
)

func TestHashiCorpVaultAppRoleAuth_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - complete set (role_id + secret_id + vault_url)",
			input: fmt.Sprintf("%s hashicorp:\n role_id = '%s'\nsecret_id = '%s'\nvault_url = '%s'", keyword, validRoleId, validSecretId, validVaultUrl),
			want:  []string{fmt.Sprintf("%s:%s", validRoleId, validSecretId)},
		},
		{
			name:  "valid pattern - only role_id (incomplete set)",
			input: fmt.Sprintf("%s role_id = '%s'", keyword, validRoleId),
			want:  []string{},
		},
		{
			name:  "valid pattern - only secret_id (incomplete set)",
			input: fmt.Sprintf("%s secret_id = '%s'", keyword, validSecretId),
			want:  []string{},
		},
		{
			name:  "valid pattern - role_id + secret_id but no vault_url (incomplete set)",
			input: fmt.Sprintf("%s config:\nrole_id = '%s'\nsecret_id = '%s'", keyword, validRoleId, validSecretId),
			want:  []string{},
		},
		{
			name:  "valid pattern - ignore duplicates in complete set",
			input: fmt.Sprintf("%s role_id = '%s' | '%s'\nsecret_id = '%s'\nvault_url = '%s'", keyword, validRoleId, validRoleId, validSecretId, validVaultUrl),
			want:  []string{fmt.Sprintf("%s:%s", validRoleId, validSecretId)},
		},
		{
			name: "valid pattern - multiple credentials with vault_url",
			input: fmt.Sprintf("%s config:\nrole_id1 = '%s'\nrole_id2 = '%s'\nsecret_id1 = '%s'\nsecret_id2 = '%s'\nvault_url = '%s'",
				keyword, validRoleId,
				"abcdef12-3456-7890-abcd-ef1234567890",
				validSecretId,
				"FEDCBA09-8765-4321-FEDC-BA0987654321",
				validVaultUrl),
			want: []string{
				fmt.Sprintf("%s:%s", validRoleId, validSecretId),
				fmt.Sprintf("%s:%s", validRoleId, "FEDCBA09-8765-4321-FEDC-BA0987654321"),
				fmt.Sprintf("%s:%s", "abcdef12-3456-7890-abcd-ef1234567890", validSecretId),
				fmt.Sprintf("%s:%s", "abcdef12-3456-7890-abcd-ef1234567890", "FEDCBA09-8765-4321-FEDC-BA0987654321"),
			},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validRoleId),
			want:  []string{},
		},
		{
			name:  "invalid pattern - role_id with invalid character",
			input: fmt.Sprintf("%s role_id = '%s'\nvault_url = '%s'", keyword, invalidRoleId, validVaultUrl),
			want:  []string{},
		},
		{
			name:  "invalid pattern - secret_id with invalid character",
			input: fmt.Sprintf("%s secret_id = '%s'\nvault_url = '%s'", keyword, invalidSecretId, validVaultUrl),
			want:  []string{},
		},
		{
			name:  "invalid pattern - role_id too short",
			input: fmt.Sprintf("%s role_id = '%s'\nvault_url = '%s'", keyword, "12345678-1234-1234-1234-123456789ab", validVaultUrl),
			want:  []string{},
		},
		{
			name:  "invalid pattern - secret_id too long",
			input: fmt.Sprintf("%s secret_id = '%s'\nvault_url = '%s'", keyword, "87654321-4321-4321-4321-CBA9876543211", validVaultUrl),
			want:  []string{},
		},
		{
			name:  "invalid pattern - role_id with uppercase (should be lowercase only)",
			input: fmt.Sprintf("%s role_id = '%s'\nvault_url = '%s'", keyword, "12345678-1234-1234-1234-123456789ABC", validVaultUrl),
			want:  []string{},
		},
		{
			name:  "invalid pattern - missing hyphens in UUIDs",
			input: fmt.Sprintf("%s role_id = '%s'\nsecret_id = '%s'\nvault_url = '%s'", keyword, "123456781234123412341234567890ab", "87654321432143214321CBA987654321", validVaultUrl),
			want:  []string{},
		},
		{
			name:  "valid pattern - alternative service keyword",
			input: fmt.Sprintf("hashicorp role_id = '%s'\nsecret_id = '%s'\nvault_url = '%s'", validRoleId, validSecretId, validVaultUrl),
			want:  []string{fmt.Sprintf("%s:%s", validRoleId, validSecretId)},
		},
		{
			name:  "valid pattern - vault_url without credentials",
			input: fmt.Sprintf("%s vault_url = '%s'", keyword, validVaultUrl),
			want:  []string{},
		},
		{
			name:  "invalid pattern - non-hashicorp vault url",
			input: fmt.Sprintf("%s role_id = '%s'\nsecret_id = '%s'\nvault_url = 'https://my-vault.company.com'", keyword, validRoleId, validSecretId),
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
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
