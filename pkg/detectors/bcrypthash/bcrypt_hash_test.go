package bcrypthash

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestBcryptHash_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	// Valid bcrypt hashes for testing
	validHashA := "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
	validHashB := "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	validHashY := "$2y$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid bcrypt hash $2a$",
			input: `PASSWORD_HASH="` + validHashA + `"`,
			want:  []string{validHashA},
		},
		{
			name:  "valid bcrypt hash $2b$",
			input: `BCRYPT_HASH=` + validHashB,
			want:  []string{validHashB},
		},
		{
			name:  "valid bcrypt hash $2y$",
			input: `User password hash: ` + validHashY,
			want:  []string{validHashY},
		},
		{
			name: "multiple bcrypt hashes",
			input: `
				admin: ` + validHashA + `
				user: ` + validHashB,
			want: []string{validHashA, validHashB},
		},
		{
			name:  "deduplication - repeated hash",
			input: validHashA + ` and ` + validHashA,
			want:  []string{validHashA},
		},
		{
			name:  "invalid - wrong prefix",
			input: `$3a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW`,
			want:  nil,
		},
		{
			name:  "invalid - too short",
			input: `$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi`,
			want:  nil,
		},
		{
			name:  "invalid - invalid characters",
			input: `$2a$12$R9h!cIPz0gi@URNNX3kh2OPST9#PgBkqquzi$Ss7KIUgO2t0jWMUW`,
			want:  nil,
		},
		{
			name:  "invalid - wrong cost format",
			input: `$2a$1$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords %v not found in input", d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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

func TestBcryptHash_FromData(t *testing.T) {
	validHash := "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"

	tests := []struct {
		name       string
		input      string
		wantResult []detectors.Result
	}{
		{
			name:  "bcrypt hash detected",
			input: `PASSWORD_HASH="` + validHash + `"`,
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_BcryptHash,
					Raw:          []byte(validHash),
					Verified:     false, // Bcrypt hashes cannot be verified
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if diff := cmp.Diff(
				test.wantResult,
				got,
				cmpopts.IgnoreFields(detectors.Result{}, "ExtraData", "SecretParts"),
				cmpopts.IgnoreUnexported(detectors.Result{}),
			); diff != "" {
				t.Errorf("FromData() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBcryptHash_Type(t *testing.T) {
	s := Scanner{}
	require.Equal(t, detector_typepb.DetectorType_BcryptHash, s.Type())
}

func TestBcryptHash_Keywords(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Keywords())
	require.Contains(t, s.Keywords(), "$2a$")
	require.Contains(t, s.Keywords(), "bcrypt")
}
