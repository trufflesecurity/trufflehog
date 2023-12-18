//go:build detectors
// +build detectors

package npm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestNpmTokenGeneric_Pattern(t *testing.T) {
	cases := map[string]npmPatternTestCase{
		"_authToken/top_level": {
			input: `_authToken = dL4dfTOJSL8pijHrBFPKqp2bUwLGkVotezEn8dfTPe-Qa1cP
registry = https://npm.company.com/
always-auth = true`,
			expected: "dL4dfTOJSL8pijHrBFPKqp2bUwLGkVotezEn8dfTPe-Qa1cP",
		},
		"_authToken/scoped/artifactory": {
			input: `registry=https://artifactory.example.com/artifactory/api/npm/npm/
//artifactory.example.com/artifactory/api/npm/npm/:_authToken=eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJSZ25DcnBEVXlKOV9yNElVRnNSU2hqU0E0aGpibEpjZ0M2bnJhN3ZqcTNNIn0.eyJzdWIiOiJqZnJ0QDAxY2pwdDc0N3ZyNHo0MTU4MHNiN3MxYW14XC91c2Vyc1wvYXJ0dXJvLmNhbXBvcyIsInNjcCI6ImFwcGxpZWQtcGVybWlzc2lvbnNcL2dyb3VwczpyZWFkZXJzLGRlcGxveS1kZXYtbnBtLGRlcGxveS1sb2NhbCIsImF1ZCI6ImpmcnRAMDFjanB0NzQ3dnI0ejQxNTgwc2I3czFhbXgiLCJpc3MiOiJqZnJ0QDAxY2pwdDc0N3ZyNHo0MTU4MHNiN3MxYW14XC91c2Vyc1wvYXJ0dXJvLmNhbXBvcyIsImV4cCI6MTY1NjAwNDUxOSwiaWF0IjoxNjU2MDAwOTE5LCJqdGkiOiJjOWZhM2VhNS01MzE0LTQwMzUtYjNiYy03OGNjMDJmYmM1NWMifQ.EIEPLzz9H2oQ3rKLKI_t1qtxi-G9ym6P6J5z7xWLsq79aHK3XV_E8_yuUK8giaOOdl_CaITOjl8Bt2aUVXTZKFKIOiQMLscBM4B6qGj_n4Qq8jiMwcKjnD_iWx8Wo-aNHHxgjvrRdWf-2UPIm6lSc77oZbUNAjhA5Q-W3uQRG7d50FGZpq_EEZsfbOcD7EMU2ZnvfYNTgTtmhZWfLefzB6xUF8WHgiDAVHJKQ2fKLX45Z9trc2SkKQmPBxaS-pBtKBhK15kQZ3x625KtLRr2ZwgOaJKHcg4SwuGOpyTF48nTk53SDorSj6fqlypTavVQRi-5cuSGTPrqLObk6lwpRg`,
			expected: "eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJSZ25DcnBEVXlKOV9yNElVRnNSU2hqU0E0aGpibEpjZ0M2bnJhN3ZqcTNNIn0.eyJzdWIiOiJqZnJ0QDAxY2pwdDc0N3ZyNHo0MTU4MHNiN3MxYW14XC91c2Vyc1wvYXJ0dXJvLmNhbXBvcyIsInNjcCI6ImFwcGxpZWQtcGVybWlzc2lvbnNcL2dyb3VwczpyZWFkZXJzLGRlcGxveS1kZXYtbnBtLGRlcGxveS1sb2NhbCIsImF1ZCI6ImpmcnRAMDFjanB0NzQ3dnI0ejQxNTgwc2I3czFhbXgiLCJpc3MiOiJqZnJ0QDAxY2pwdDc0N3ZyNHo0MTU4MHNiN3MxYW14XC91c2Vyc1wvYXJ0dXJvLmNhbXBvcyIsImV4cCI6MTY1NjAwNDUxOSwiaWF0IjoxNjU2MDAwOTE5LCJqdGkiOiJjOWZhM2VhNS01MzE0LTQwMzUtYjNiYy03OGNjMDJmYmM1NWMifQ.EIEPLzz9H2oQ3rKLKI_t1qtxi-G9ym6P6J5z7xWLsq79aHK3XV_E8_yuUK8giaOOdl_CaITOjl8Bt2aUVXTZKFKIOiQMLscBM4B6qGj_n4Qq8jiMwcKjnD_iWx8Wo-aNHHxgjvrRdWf-2UPIm6lSc77oZbUNAjhA5Q-W3uQRG7d50FGZpq_EEZsfbOcD7EMU2ZnvfYNTgTtmhZWfLefzB6xUF8WHgiDAVHJKQ2fKLX45Z9trc2SkKQmPBxaS-pBtKBhK15kQZ3x625KtLRr2ZwgOaJKHcg4SwuGOpyTF48nTk53SDorSj6fqlypTavVQRi-5cuSGTPrqLObk6lwpRg",
		},
		"_authToken/scoped/gitlab_old": {
			input:    `RUN npm config set "//gitlab.com/api/v4/packages/npm/:_authToken" "aB3_-9R2sPqLxY0ZwCc8D"`,
			expected: "aB3_-9R2sPqLxY0ZwCc8D",
		},
		"_authToken/scoped/gitlab_new": {
			input: `@company:registry=https://gitlab.com/api/v4/projects/12356452/packages/npm/
//gitlab.com/api/v4/projects/12356452/packages/npm/:_authToken=glpat-ijTwXA7JxJAEx7uzmVfH`,
			expected: "glpat-ijTwXA7JxJAEx7uzmVfH",
		},
		"_authToken/scoped/github": {
			input: `npm config set @company:registry=https://npm.pkg.github.com/
    npm config set //npm.pkg.github.com/:_authToken=ghp_sS4gaQUHsXSdwojekGTlaIAgJ77Wsn4D7gPO
    npm install -g @company/internal-package@1.2.3`,
			expected: "ghp_sS4gaQUHsXSdwojekGTlaIAgJ77Wsn4D7gPO",
		},
		"_authToken/scoped/google": {
			input: `//us-east1-npm.pkg.dev/company-dev-167118/project/:_authToken=ya29.c.b0Aaekm1IkdX0VHcPkEnYB8dmgL5IHi3jXTffM9hwjaNInirTSOv3hsCsJuCyswioQpO1UGkvVqReYpSW7V6sxmTv7fSPpZJeKzRQcKb6LLjApF7gFGyZMg9lUf7YBFixyGDZxaq0T-FnksK8O7KC4MSxalTe4dnl_jWXcs7FKi-FQOwsAuR1-zwRS63F1YG9fpCq2WykPhjwcbYPVlb3jpTOmIJhGpaWq7Sd5_uunWTHadgI3sCCazp_rT8xa8MS8YtyTJl716Taix4nmD-2Rertq9uS8P9AkFHMHaRvXl3W2PbNHxQtJ3fI3RRmBaVSe5WQlA1MofCol-lUN344KqfknpMfIjuXhB4h5fRB5zZ0Z2te_f0SVS1ZZ1Ox-sWVbh-2keFJ9Um0OS7O46rIOg_z7X-817qf_rIWmhQZgmk6ubI4hVR-7_lUl8lzi0ypo6Ve2wVZd6n9q8ws_RWt5k1Q_YkI0ukMe-U3a7s8F16w7r0OSFqVmhy0psYQ4-8jp79IhUbdm10l32tQhZ22UcIuBk8S4FX4c7nUIWk1Xd9xeu0JJ8Xrwd6nW24i1j-vbnMZxk0t1_5ZljUXVncxo5xjucr4WyYOmvuaS_iSaz89jUdYfxiOxWieiUVbuzZSXWvZFFZrkQFggeq3Vq2hmj6Zls_W8Bm9o8-8020S6692rB5pf8h6b-RI4zig928xufkWtVfMXU3fth24eVWqYIIy_qQh6UcJ1_VZF8uvMYoowUu3aQShisof8eoi8qQixO4YIJ2VSSctnFvthQUJ_0p5Vt9YQSyx_XqS8_1VeaMpnwWMkXXSVZrflo9Ieb_s-V9RlYB23attr3oR0_5Q95rzgJXivy1-UmhIO3iSn4QWZceeJynjv1MB01tyJd35icywcmc5j5onQl5F3x0_rdZSZyhVduujy6gFk1yBnWidRFg38QU4Y2_ZwS68e66SjYXddORq9-xaw6fjO4qkb1n6i6zb00eX1mY2rq8UpqQ6v4t1n4n4h9M3
@fortawesome:registry=https://npm.fontawesome.com/`,
			expected: "ya29.c.b0Aaekm1IkdX0VHcPkEnYB8dmgL5IHi3jXTffM9hwjaNInirTSOv3hsCsJuCyswioQpO1UGkvVqReYpSW7V6sxmTv7fSPpZJeKzRQcKb6LLjApF7gFGyZMg9lUf7YBFixyGDZxaq0T-FnksK8O7KC4MSxalTe4dnl_jWXcs7FKi-FQOwsAuR1-zwRS63F1YG9fpCq2WykPhjwcbYPVlb3jpTOmIJhGpaWq7Sd5_uunWTHadgI3sCCazp_rT8xa8MS8YtyTJl716Taix4nmD-2Rertq9uS8P9AkFHMHaRvXl3W2PbNHxQtJ3fI3RRmBaVSe5WQlA1MofCol-lUN344KqfknpMfIjuXhB4h5fRB5zZ0Z2te_f0SVS1ZZ1Ox-sWVbh-2keFJ9Um0OS7O46rIOg_z7X-817qf_rIWmhQZgmk6ubI4hVR-7_lUl8lzi0ypo6Ve2wVZd6n9q8ws_RWt5k1Q_YkI0ukMe-U3a7s8F16w7r0OSFqVmhy0psYQ4-8jp79IhUbdm10l32tQhZ22UcIuBk8S4FX4c7nUIWk1Xd9xeu0JJ8Xrwd6nW24i1j-vbnMZxk0t1_5ZljUXVncxo5xjucr4WyYOmvuaS_iSaz89jUdYfxiOxWieiUVbuzZSXWvZFFZrkQFggeq3Vq2hmj6Zls_W8Bm9o8-8020S6692rB5pf8h6b-RI4zig928xufkWtVfMXU3fth24eVWqYIIy_qQh6UcJ1_VZF8uvMYoowUu3aQShisof8eoi8qQixO4YIJ2VSSctnFvthQUJ_0p5Vt9YQSyx_XqS8_1VeaMpnwWMkXXSVZrflo9Ieb_s-V9RlYB23attr3oR0_5Q95rzgJXivy1-UmhIO3iSn4QWZceeJynjv1MB01tyJd35icywcmc5j5onQl5F3x0_rdZSZyhVduujy6gFk1yBnWidRFg38QU4Y2_ZwS68e66SjYXddORq9-xaw6fjO4qkb1n6i6zb00eX1mY2rq8UpqQ6v4t1n4n4h9M3",
		},
		"_authToken/scoped/gemfury": {
			input: `# always-auth=true
# registry=https://npm.fury.io/company/
# //npm.fury.io/company/:_authToken=Du4CPz7SsRom1Mz8hbSR`,
			expected: "Du4CPz7SsRom1Mz8hbSR",
		},
		"_authToken/scoped/other(1)": {
			input: `//npm.company.com/:_authToken="VVEvgoi7lSkBaCd4s0Gb0A=="
always_auth=true
registry=https://npm.company.com/
user=jdoe`,
			expected: "VVEvgoi7lSkBaCd4s0Gb0A==",
		},
		"_authToken/scoped/other(2)": {
			input: `loglevel=silent
registry=https://npm.company.de:4873/
@babel:registry=https://registry.npmjs.org
//npm.company.de:4873/:_authToken="zZcZwiAWuyyspOAGrzAlE/LBH55oyfzsIOQvPsQ/5n0="`,
			expected: "zZcZwiAWuyyspOAGrzAlE/LBH55oyfzsIOQvPsQ/5n0=",
		},
		"_authToken/scoped/other(3)": {
			input: `strict-ssl=true
//r.privjs.com/:_authToken=JWT_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyVVVJRCI6ImI1NjM1NDdmLTQ5NTQtNGVkOS04ZDI4LTkzZjFlYjE2YjgwYyIsInVzZXJuYW1lIjoiZGFya28iLCJpYXQiOjE2NzAzMzQwMTV9.itmCA6WviKLcGwahuV-K2cvDtDkM_j7o_NjZrdzWu0M
@module-federation:registry=https://r.privjs.com`,
			expected: "JWT_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyVVVJRCI6ImI1NjM1NDdmLTQ5NTQtNGVkOS04ZDI4LTkzZjFlYjE2YjgwYyIsInVzZXJuYW1lIjoiZGFya28iLCJpYXQiOjE2NzAzMzQwMTV9.itmCA6WviKLcGwahuV-K2cvDtDkM_j7o_NjZrdzWu0M",
		},
		"NPM_TOKEN/buildkite": {
			input: `steps:
  - label: 'Install'
    command: NODE_ENV=development yarn install --frozen-lockfile
    plugins:
      - ssh://git@github.com/foo/bar-plugin#v0.0.18:
        secrets:
          NPM_TOKEN: "x3jAqghGq90/oN3mM3rWxQ8KaD4nw9g6bw/dL4dfTOJSL8pijHrBFPK6p7bUwLGkVotezEn8dfTPe-Qa1cP"`,
			expected: "x3jAqghGq90/oN3mM3rWxQ8KaD4nw9g6bw/dL4dfTOJSL8pijHrBFPK6p7bUwLGkVotezEn8dfTPe-Qa1cP",
		},
		"NPM_TOKEN/cloudbuild": {
			input: `secrets:
- kmsKeyName: projects/myproject/locations/global/keyRings/cloud-build/cryptoKeys/cloud-build
  secretEnv:
    NPM_TOKEN: CiQAwtE8WoPa1sNqAQJZ1WMODuJooVmO6zihz2hAZOfUmDsgogUSTQCq8yp8qgltY+8jWpAR9GuS1JaVhd+fTVRilqLtdi2yXSdiDPTzLhZ+30bMlAOcoc0PxhCBn3JOpn8H1xshX+mG8yK7xog2Uq+CLVx/

timeout: 60s`,
			expected: "CiQAwtE8WoPa1sNqAQJZ1WMODuJooVmO6zihz2hAZOfUmDsgogUSTQCq8yp8qgltY+8jWpAR9GuS1JaVhd+fTVRilqLtdi2yXSdiDPTzLhZ+30bMlAOcoc0PxhCBn3JOpn8H1xshX+mG8yK7xog2Uq+CLVx/",
		},

		// Invalid
		"invalid/_authToken/top_level": {
			input: `_authToken = ${NPM_TOKEN}
registry = https://npm.company.com/`,
		},
		"invalid/_authToken/v1_pattern": {
			input: `echo //nexus.company.com/repository/npm-registry/:_authToken=NpmToken.fe093789-9551-3238-a766-9d2b694f2600 >> .npmrc`,
		},
		"invalid/_authToken/v2_pattern": {
			input: `  //registry.npmjs.org/:_authToken=npm_ArCHsOJAC3gMXmzaVwUts00QfWWUrW4UuewA`,
		},
	}

	testPattern(t, ScannerGeneric{}, cases)
}

func TestNpmTokenGeneric_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("NPM_TOKEN_GENERIC")
	inactiveSecret := testSecrets.MustGetField("NPM_TOKEN_GENERIC_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   ScannerGeneric
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified",
			s:    ScannerGeneric{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a npm_token_generic secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NpmToken,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    ScannerGeneric{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a npm_token_generic secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NpmToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
			s:    ScannerGeneric{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    ScannerGeneric{npmScanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)}},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a npm_token_generic secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NpmToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    ScannerGeneric{npmScanner{client: common.ConstantResponseHttpClient(404, "")}},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a npm_token_generic secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_NpmToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("npm_token_generic.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("npm_token_generic.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := ScannerGeneric{}
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
