package azurecontainerregistry

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureContainerRegistry_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "pwd",
			input: `source storage.env
				ACR=smpldev.azurecr.io
				ACRUSER=smpldev
				ACRPWD=Cw8xeDNK6Bub3p61aq5ij/TiVvtBicpTj5rverVezj+ACRBPkEcx
				CONTAINER=storage-svc:latest`,
			want: []string{`{"username":"smpldev","password":"Cw8xeDNK6Bub3p61aq5ij/TiVvtBicpTj5rverVezj+ACRBPkEcx"}`},
		},
		{
			name: "password",
			input: `    - name: Deploy to ARC
						uses: azure/docker-login@v1
						with:
								login-server: crmshopacr.azurecr.io
								username: crmshopacr
								password: o9uXSjWlUdRwAeGP2xGSfGy+25vetsONo3Mq13fksa+ACRBXyFsY
						- run: |`,
			want: []string{`{"username":"crmshopacr","password":"o9uXSjWlUdRwAeGP2xGSfGy+25vetsONo3Mq13fksa+ACRBXyFsY"}`},
		},
		{
			name: "docker cli login",
			input: `docker login dvacr00.azurecr.io -u dvacr00 -p Ljc+1lq0U0+c3jHlMHxSxAhCipKt6zU43HfMle/Ymj+ACRAKcPHy
					docker push dvacr00.azurecr.io/foo-alpine:3.18`,
			want: []string{`{"username":"dvacr00","password":"Ljc+1lq0U0+c3jHlMHxSxAhCipKt6zU43HfMle/Ymj+ACRAKcPHy"}`},
		},
		{
			name:  "request body",
			input: `"registries":[{"identity":"","passwordSecretRef":"registry-password","server":"cr2bxwtqgom2oo.azurecr.io","username":"cr2bxwtqgom2oo"}],"secrets":[{"name":"registry-password","value":"VP2rvkuld42mr3jNjM+rVbvIzVuZxwncKWyVU5UIad+ACRBivL0B"}]}`,
			want:  []string{`{"username":"cr2bxwtqgom2oo","password":"VP2rvkuld42mr3jNjM+rVbvIzVuZxwncKWyVU5UIad+ACRBivL0B"}`},
		},
		{
			name: "README",
			input: `# AZURE-CICD-Deployment-with-Github-Actions
					## Save pass:

					s3cEZKH3yytiVnJ3h+eI3qhhzf9l1vNwEi1+q+WGdd+ACRCZ7JD6


					## Run from terminal:

					docker build -t testapp.azurecr.io/chicken:latest .
					`,
			want: []string{`{"username":"testapp","password":"s3cEZKH3yytiVnJ3h+eI3qhhzf9l1vNwEi1+q+WGdd+ACRCZ7JD6"}`},
		},
		// TODO:
		//{
		//	name:  "az cli login",
		//	input: `az acr login --name tstcopilotacr --username tstcopilotacr --password 9iZkJiOTKeEsQDfgoobtCYU47EEDs9UvU4L8NErLV+ACRACptmc`,
		//	want:  []string{},
		//},
		//{
		//	name:  "",
		//	input: ``,
		//	want:  []string{},
		{
			name: "invalid pattern",
			input: `
				azure:
					url: http://invalid.azurecr.io.azure.com
					secret: BXIMbhBlC3=5hIbqCEKvq7op!V2ZfO0XWbcnasZmPm/AJfQqdcnt/+2Ytxc1hDq1m/
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
