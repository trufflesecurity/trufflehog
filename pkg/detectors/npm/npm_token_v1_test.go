//go:build detectors
// +build detectors

package npm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestNpmTokenV1_Pattern(t *testing.T) {
	cases := map[string]npmPatternTestCase{
		"npmrc/_authToken/top_level": {
			input: `registry=https://nexus.company.com/repository/npm-group/
_authToken=NpmToken.3e9adc26-5c1b-3fdf-901f-6df392a48616`,
			expected: "3e9adc26-5c1b-3fdf-901f-6df392a48616",
		},
		"npmrc/_authToken/scoped/npm": {
			input: `loglevel=silent
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=fcb3b15d-4d4a-44dc-b92d-13ee9d25582d`,
			expected: "fcb3b15d-4d4a-44dc-b92d-13ee9d25582d",
		},
		"npmrc/_authToken/scoped/nexus": {
			input: `  echo email=jdoe@company.com > .npmrc
  echo always-auth=true >> .npmrc
  echo registry=https://nexus.company.com:8443/repository/npm-registry/ >> .npmrc
  echo //nexus.company.com/repository:8443/npm-registry/:_authToken=NpmToken.de093289-9551-3238-a766-9d2c694f2600 >> .npmrc`,
			expected: "de093289-9551-3238-a766-9d2c694f2600",
		},
		"npmrc/_authToken/scopegd/other(1)": {
			input: `@fontawesome:registry=https://npm.fontawesome.com/
//npm.fontawesome.com/:_authToken=E8EC7793-A630-49AA-3351-6887EE647296`,
			expected: "E8EC7793-A630-49AA-3351-6887EE647296",
		},
		"yarn/npmAuthToken/scoped": {
			input: `npmScopes:
  fortawesome:
    npmAlwaysAuth: true
    npmRegistryServer: "https://npm.fontawesome.com/"
    npmAuthToken: "${20FCC725-C7FF-4BBF-3DE8-632C89A16C87}"`,
			expected: "20FCC725-C7FF-4BBF-3DE8-632C89A16C87",
		},
		"misc(1)": {
			input: `CI: "true"
            NPM_PUBLISH_URL: "http://nexus3.company.net:8081/repository/npm-releases/"
            NPM_PUBLISH_TOKEN: "b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb"`,
			expected: "b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb",
		},
		"misc(2)": {
			input: `- name: NPM_PUBLISH_TOKEN
  description: "Npm user used when upload artifacts"
  required: true
  value: "NpmToken.b5505337-ffb2-3fac-8b3a-fcd81b8ab8fb"`,
			expected: "b5505337-ffb2-3fac-8b3a-fcd81b8ab8fb",
		},
		"misc(3)": {
			input: `root@4f5ec7bfe603:/<span class="token comment"># cd &amp;&amp; cat .npmrc </span>
//192.168.1.253:8081/repository/npm-group-local/:_authToken<span class="token operator">=</span>NpmToken.7385beb7-2f92-3295-8ccf-8020132d6232`,
			expected: "7385beb7-2f92-3295-8ccf-8020132d6232",
		},
		"misc(4)": {
			input:    `ENV NPM_TOKEN "16b46f03-f1fb-4dce-9a98-c7e685751e67"`,
			expected: "16b46f03-f1fb-4dce-9a98-c7e685751e67",
		},
		"misc(5)": {
			input: // https://github.com/arnaud-deprez/jenkins-docker-openshift/blob/60bb4dbe4d5484ff3f81697c26892dda4cd33930/charts/jenkins-openshift/values.yaml#L209
			`            CI: "true"
            NPM_MIRROR_URL: "http://nexus3:8081/repository/npm-public/"
            NPM_PUBLISH_URL: "http://nexus3:8081/repository/npm-releases/"
            NPM_PUBLISH_TOKEN: "b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb"`,
			expected: "b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb",
		},

		// Invalid
		"invalid/_authToken/variable": {
			input: `//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_AUTH_TOKEN}`,
		},
		"invalid/default": {
			input: `assert(registry, 'registry not set, example: "https://nexus.foo.com/repository/mynpm/"')
const tokenErrorMsg =  'npm token invalid, example: "NpmToken.00000000-0000-0000-0000-000000000000" before base64 encoded'`,
		},
		"invalid/not_uuid": {
			input: `# .npmrc
# @ngiq:registry=https://registry.corp.net/repository/npm-group
# //registry.corp.net/repository/:_authToken=NpmToken.xxxx`,
		},
	}
	testPattern(t, ScannerV1{}, cases)
}

func TestNpmTokenV1_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("NPM_TOKEN_V1")
	inactiveSecret := testSecrets.MustGetField("NPM_TOKEN_V1_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		s       ScannerV1
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "found, verified",
			s:    ScannerV1{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a npm secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NpmToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    ScannerV1{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a npm secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NpmToken,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    ScannerV1{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScannerV1{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NpmTokenV1.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("NpmTokenV1.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromDataV1(benchmark *testing.B) {
	ctx := context.Background()
	s := ScannerV1{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
