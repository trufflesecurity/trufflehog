// There is no integration test for this detector. SonarQube Server tokens only
// work on a server the user runs, and there is no public cloud endpoint to
// verify against, so there is no live instance and credential we can keep in
// the test secrets.
package sonarqube

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestSonarQube_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern user token",
			input: "token = squ_9747c1e823fe6696482cf7bb74e9551db87f2bdf",
			want:  []string{"squ_9747c1e823fe6696482cf7bb74e9551db87f2bdf"},
		},
		{
			name:  "valid pattern global analysis token",
			input: "SONAR_TOKEN=sqa_dc13d164f1302e6b4c1f403e58ab80c545491887",
			want:  []string{"sqa_dc13d164f1302e6b4c1f403e58ab80c545491887"},
		},
		{
			name:  "valid pattern project analysis token",
			input: `property "sonar.token","sqp_694069134ff43e17eb2a1ca18ed20b13397dce88"`,
			want:  []string{"sqp_694069134ff43e17eb2a1ca18ed20b13397dce88"},
		},
		{
			name: "finds all matches",
			input: `
				[DEBUG] Using token=squ_9747c1e823fe6696482cf7bb74e9551db87f2bdf
				[DEBUG] Using token=sqa_dc13d164f1302e6b4c1f403e58ab80c545491887
				[DEBUG] Using token=sqp_694069134ff43e17eb2a1ca18ed20b13397dce88
			`,
			want: []string{
				"squ_9747c1e823fe6696482cf7bb74e9551db87f2bdf",
				"sqa_dc13d164f1302e6b4c1f403e58ab80c545491887",
				"sqp_694069134ff43e17eb2a1ca18ed20b13397dce88",
			},
		},
		{
			name: "invalid pattern",
			input: `
				[DEBUG] Using token=squ_foo
				[DEBUG] Using token=sqa_9747C1E823FE6696482CF7BB74E9551DB87F2BDF
				[DEBUG] Using token=sqp_9747c1e823fe6696482cf7bb74e9551db87f2bdf0
				[DEBUG] Using token=sqx_9747c1e823fe6696482cf7bb74e9551db87f2bdf
			`,
			want: []string{},
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
				actual[string(r.Raw)] = struct{}{}
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

func TestSonarQube_FindEndpoints(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "gradle property, any port", input: `property "sonar.host.url","http://localhost:9999"`, want: []string{"http://localhost:9999"}},
		{name: "maven property", input: "<sonar.host.url>https://sonar.example.com</sonar.host.url>", want: []string{"https://sonar.example.com"}},
		{name: "properties file", input: "sonar.host.url=https://sonar.example.com/", want: []string{"https://sonar.example.com"}},
		{name: "env var", input: "SONAR_HOST_URL=sonar.example.com:8080", want: []string{"sonar.example.com:8080"}},
		{name: "yaml", input: "SONAR_URL: https://sonar.example.com", want: []string{"https://sonar.example.com"}},
		{name: "host and port without a key is not used", input: "ssh sonar.example.com:9000", want: nil},
		{name: "docker port mapping is not a host", input: "ports: - 9000:9000", want: nil},
		{name: "same host twice is returned once", input: "sonar.host.url=https://a.example.com:9000\nSONAR_HOST_URL=https://a.example.com:9000", want: []string{"https://a.example.com:9000"}},
		{name: "variable is not a host", input: "sonar.host.url=${SONAR_URL}", want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := findEndpoints(test.input)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("diff: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestSonarQube_NoEndpointMessage(t *testing.T) {
	input := "token = squ_9747c1e823fe6696482cf7bb74e9551db87f2bdf"

	s := Scanner{}
	s.UseFoundEndpoints(true) // the engine turns this on by default
	results, err := s.FromData(context.Background(), true, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].Verified)
	require.Contains(t, results[0].ExtraData["message"], "--verifier SonarQube=")

	// with a host in the data there is something to verify, so no message
	input += "\nsonar.host.url=http://localhost:9999"
	results, err = s.FromData(context.Background(), false, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Empty(t, results[0].ExtraData["message"])
}
