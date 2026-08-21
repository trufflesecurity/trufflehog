package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validUriPattern           = "postgres://sN19x:d7N8bs@1.2.3.4:5432"
	invalidUriPattern         = "?ostgres://sN19x:d7N8bs@1.2.3.4:5432"
	validConnStrPartPattern   = "gVmMTdkwLwmZljcIOXhEmuZ='.jD#=-;|9tD!r^6('"
	invalidConnStrPartPattern = "gVmMTdkwLwmZljcIOXhEmu?='.jD#=-;|9tD!r^6('"
	keyword                   = "postgres"
)

func TestPostgres_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword postgres",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validUriPattern, keyword, validConnStrPartPattern),
			want:  []string{validUriPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidUriPattern, keyword, invalidConnStrPartPattern),
			want:  []string{},
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

func TestPostgres_ExtraData(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		wantHost     string
		wantUsername string
		wantDatabase string
	}{
		{
			name:         "standard URI with database",
			data:         "postgres://myuser:mypass@dbhost.example.com:5432/mydb",
			wantHost:     "dbhost.example.com:5432",
			wantUsername: "myuser",
			wantDatabase: "mydb",
		},
		{
			name:         "postgresql scheme",
			data:         "postgresql://admin:secret@10.0.0.1:5433/production",
			wantHost:     "10.0.0.1:5433",
			wantUsername: "admin",
			wantDatabase: "production",
		},
		{
			name:         "without database",
			data:         "postgres://sN19x:d7N8bs@1.2.3.4:5432?sslmode=require",
			wantHost:     "1.2.3.4:5432",
			wantUsername: "sN19x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{detectLoopback: true}
			results, err := s.FromData(context.Background(), false, []byte(tt.data))
			require.NoError(t, err)
			require.NotEmpty(t, results, "expected at least one result")

			r := results[0]
			assert.Equal(t, tt.wantHost, r.ExtraData["host"])
			assert.Equal(t, tt.wantUsername, r.ExtraData["username"])
			assert.Equal(t, tt.wantDatabase, r.ExtraData["database"])
			assert.Contains(t, r.ExtraData, "sslmode", "ExtraData[sslmode] should still be present")
		})
	}
}

func TestIsNeonHost(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		host string
		want bool
	}{
		{host: "ep-falling-feather-aimmxil4.c-4.us-east-1.aws.neon.tech", want: true},
		{host: "EP.NEON.TECH", want: true},
		{host: "db.example.com", want: false},
		{host: "neon.tech.evil.com", want: false},
		{host: "neon.tech", want: false},
		{host: "", want: false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isNeonHost(tc.host))
		})
	}
}

func TestPgxConnStringOmitsClientOnlyParams(t *testing.T) {
	t.Parallel()

	got := pgxConnString(map[string]string{
		pgHost:       "ep-example.us-east-1.aws.neon.tech",
		pgPort:       "5432",
		pgUser:       "user",
		pgPassword:   "secret",
		pgDbname:     "neondb",
		pgSslmode:    pgSslmodeRequire,
		pgDbType:     "postgres",
		pgRequiressl: "1",
	})

	assert.Contains(t, got, "host='ep-example.us-east-1.aws.neon.tech'")
	assert.Contains(t, got, "sslmode='require'")
	assert.NotContains(t, got, "db_type=")
	assert.NotContains(t, got, "requiressl=")
}

func TestClassifyPostgresVerifyError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		err          error
		dbName       string
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "invalid password code",
			err:          &pgconn.PgError{Code: "28P01", Message: "password authentication failed"},
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "missing database code",
			err:          &pgconn.PgError{Code: "3D000", Message: `database "app" does not exist`},
			dbName:       "app",
			wantVerified: true,
			wantErr:      false,
		},
		{
			name:         "password failure by message",
			err:          errors.New("password authentication failed for user \"x\""),
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "missing database by message",
			err:          errors.New(`database "postgres" does not exist`),
			wantVerified: true,
			wantErr:      false,
		},
		{
			name:         "indeterminate error",
			err:          errors.New("connection refused"),
			wantVerified: false,
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verified, err := classifyPostgresVerifyError(tc.err, tc.dbName)
			assert.Equal(t, tc.wantVerified, verified)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPostgres_FromDataWithIgnorePattern(t *testing.T) {
	s := New(
		WithIgnorePattern([]string{
			`1\.2\.3\.4`,
		}))
	got, err := s.FromData(context.Background(), false, []byte(validUriPattern))
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestPostgres_RawVsPrimarySecret(t *testing.T) {
	s := Scanner{}
	input := "postgres://user:pass@host/dbname"
	results, err := s.FromData(context.Background(), false, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	expectedRaw := "postgres://user:pass@host:5432"
	assert.Equal(t, expectedRaw, string(res.Raw))
	assert.Equal(t, expectedRaw, string(res.RawV2))
	assert.Equal(t, input, res.GetPrimarySecretValue())
}
