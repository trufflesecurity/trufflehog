package azuresastoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureSASToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
	AZURE_BLOB_SAS_TOKEN=sp=r&st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c&sig=WSdF9YeZhvrbs%2B%2B1f8ZdDBzEe7fBJ%2BenuaXQ%2BJ9WOw0%3D
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/trufflesecurity
	`,
			want: []string{"https://trufflesecurity.blob.core.windows.net/trufflesecuritysp=r&st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c&sig=WSdF9YeZhvrbs%2B%2B1f8ZdDBzEe7fBJ%2BenuaXQ%2BJ9WOw0%3D"},
		},
		{
			name: "valid pattern with ip",
			input: `
	AZURE_BLOB_SAS_TOKEN=sp=rcwl&st=2025-03-10T06:58:25Z&se=2025-03-10T14:58:25Z&sip=168.1.6.50&spr=https&sv=2022-11-02&sr=c&sig=c%2BUXo%2FJwf%2FGHomqYaw6tyRykKMaAnyikkf8nS7btD3DYg%3D
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/trufflesecurity
	`,
			want: []string{"https://trufflesecurity.blob.core.windows.net/trufflesecuritysp=rcwl&st=2025-03-10T06:58:25Z&se=2025-03-10T14:58:25Z&sip=168.1.6.50&spr=https&sv=2022-11-02&sr=c&sig=c%2BUXo%2FJwf%2FGHomqYaw6tyRykKMaAnyikkf8nS7btD3DYg%3D"},
		},
		{
			name: "valid pattern with ip range",
			input: `
	AZURE_BLOB_SAS_TOKEN=sp=rcwl&st=2025-03-10T06:58:25Z&se=2025-03-10T14:58:25Z&sip=168.1.6.50-168.1.6.80&spr=https&sv=2022-11-02&sr=c&sig=RiA6rO2VwFNZ73trWyY6fsasg0ViUp0k3sDxcl6aA1Rtg%3D
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/trufflesecurity
	`,
			want: []string{"https://trufflesecurity.blob.core.windows.net/trufflesecuritysp=rcwl&st=2025-03-10T06:58:25Z&se=2025-03-10T14:58:25Z&sip=168.1.6.50-168.1.6.80&spr=https&sv=2022-11-02&sr=c&sig=RiA6rO2VwFNZ73trWyY6fsasg0ViUp0k3sDxcl6aA1Rtg%3D"},
		},
		{
			name: "valid pattern without https",
			input: `
	AZURE_BLOB_SAS_TOKEN=sp=rcwl&st=2025-03-10T06:58:25Z&se=2025-03-10T14:58:25Z&sv=2022-11-02&sr=c&sig=OYbYoPKW7vVGjFMBu2QDDW%2BlpoShcxawVHR91NQPosY8%3D
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/trufflesecurity
	`,
			want: []string{"https://trufflesecurity.blob.core.windows.net/trufflesecuritysp=rcwl&st=2025-03-10T06:58:25Z&se=2025-03-10T14:58:25Z&sv=2022-11-02&sr=c&sig=OYbYoPKW7vVGjFMBu2QDDW%2BlpoShcxawVHR91NQPosY8%3D"},
		},
		{
			name: "valid pattern with blob url",
			input: `
	AZURE_BLOB_SAS_TOKEN=sp=r&st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c&sig=WSdF9YeZhvrbs%2B%2B1f8ZdDBzEe7fBJ%2BenuaXQ%2BJ9WOw0%3D
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/trufflesecurity/test_blob.txt
	`,
			want: []string{"https://trufflesecurity.blob.core.windows.net/trufflesecurity/test_blob.txtsp=r&st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c&sig=WSdF9YeZhvrbs%2B%2B1f8ZdDBzEe7fBJ%2BenuaXQ%2BJ9WOw0%3D"},
		},
		{
			// Storage Explorer emits the parameters in a different order (sv first,
			// sp last) and URL-encodes the ':' in the timestamps as %3A. See #4732.
			name: "valid pattern, alternate order with url-encoded timestamps",
			input: `
	https://accountname.blob.core.windows.net/sorted?sv=2023-01-03&st=2025-06-18T08%3A45%3A11Z&se=2025-06-19T08%3A45%3A11Z&sr=c&sp=r&sig=ow2a1XbXmD4%2BEv9LBUkek8R%2FrAjvrQFpenUbzztILn8%3D
	`,
			want: []string{"https://accountname.blob.core.windows.net/sortedsv=2023-01-03&st=2025-06-18T08%3A45%3A11Z&se=2025-06-19T08%3A45%3A11Z&sr=c&sp=r&sig=ow2a1XbXmD4%2BEv9LBUkek8R%2FrAjvrQFpenUbzztILn8%3D"},
		},
		{
			name: "non-sas query string is ignored",
			input: `
	AZURE_BLOB_QUERY=comp=list&restype=container&maxresults=100
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/trufflesecurity
	`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
	AZURE_BLOB_SAS_TOKEN=st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/12trufflesecurity
	`,
			want: nil,
		},
		{
			name: "invalid pattern with invalid permission",
			input: `
	AZURE_BLOB_SAS_TOKEN=sp=rqx&st=2025-03-04T07:24:52Z&se=2025-04-04T15:24:52Z&spr=https&sv=2022-11-02&sr=c&sig=WSdF9YeZhvrbs%2B%2B1f8ZdDBzEe7fBJ%2BenuaXQ%2BJ9WOw0%3D
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/12trufflesecurity
	`,
			want: nil,
		},
		{
			name: "invalid pattern with invalid ip",
			input: `
	AZURE_BLOB_SAS_TOKEN=sp=rcwl&st=2025-03-10T06:58:25Z&se=2025-03-10T14:58:25Z&sip=168.1.6&spr=https&sv=2022-11-02&sr=c&sig=c%2BUXo%2FJwf%2FGHomqYaw6tyRykKMaAnyikkf8nS7btD3DYg%3D
	AZURE_BLOB_SAS_URL=https://trufflesecurity.blob.core.windows.net/trufflesecurity
	`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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
