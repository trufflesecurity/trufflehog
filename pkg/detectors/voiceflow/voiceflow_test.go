//go:build detectors
// +build detectors

package voiceflow

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestVoiceflow_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
	}{
		// True positives
		// https://github.com/funDAOmental/endlessquest/blob/5c008f7c6a7e58c45a88b72fef4b965c258d665c/Voiceflow/agent-api/index.js#L6
		{
			name: `valid_result1`,
			data: `// z0MG IT'S NOT A SECRET (but we'll delete it)
const API_KEY = "VF.DM.6469b4e5909a470007b96250.k4ip0SMy84jWlCsF"; // it should look like this: VF.DM.XXXXXXX.XXXXXX... keep this a secret!`,
			shouldMatch: true,
			match:       `VF.DM.6469b4e5909a470007b96250.k4ip0SMy84jWlCsF`,
		},
		// https://github.com/sherifButt/ll-site/blob/b98b268214324da42a84e996e4c03c242e122680/src/components/Chatbot.jsx#L14
		{
			name: `valid_result2`,
			data: `  const runtime = useRuntime({
    verify: { authorization: 'VF.DM.652da078cde70b0008e1c5df.zsIo23VTxNXKfb9f' },
    session: { userID: 'user_123' },
  });`,
			shouldMatch: true,
			match:       `VF.DM.652da078cde70b0008e1c5df.zsIo23VTxNXKfb9f`,
		},
		// https://github.com/the-vv/Voiceflow-chatbot/blob/324db17693dd46387ea7a020e92c4e79b94306c6/src/app/chat/chat.component.ts#L27
		{
			name: `valid_result3`,
			data: `    this.http.delete('https://general-runtime.voiceflow.com/state/user/TEST_USER', {
      headers: {
        Authorization: "VF.DM.652ecc210267ec00078fc726.ZFPdEwvU0d1jiIMq"
      }
    }).subscribe(res => {
      this.loading = false;
      this.doPrompt('', { action: { type: 'launch' } });
    })`,
			shouldMatch: true,
			match:       `VF.DM.652ecc210267ec00078fc726.ZFPdEwvU0d1jiIMq`,
		},
		// https://github.com/legionX7/Graduation-Project-API/blob/451431771d3fba1d8c634b8855274b414d7aed6d/mainAPI.py#L547
		{
			name: `valid_result4`,
			data: `
API_KEY = 'VF.DM.646388eb1419c80007bbbaa4.XHOqETFO3cvTxlGl'
VERSION_ID = '646bc'`,
			shouldMatch: true,
			match:       `VF.DM.646388eb1419c80007bbbaa4.XHOqETFO3cvTxlGl`,
		},
		// https://github.com/voiceflow/general-runtime/blob/master/tests/runtime/lib/DataAPI/utils.unit.ts
		{
			name: `valid_result5`,
			data: ` it('extracts ID from a Dialog Manager API key', () => {
      // eslint-disable-next-line no-secrets/no-secrets
      const key = 'VF.DM.628d5d92faf688001bda7907.dmC8KKO1oX8JO5ai';
      const result = utils.extractAPIKeyID(key);

      expect(result).to.equal('628d5d92faf688001bda7907');
    });`,
			shouldMatch: true,
			match:       `VF.DM.628d5d92faf688001bda7907.dmC8KKO1oX8JO5ai`,
		},
		{
			name: `valid_result6_legacy`,
			data: `    it('extracts ID from a Workspace API key', () => {
      // eslint-disable-next-line no-secrets/no-secrets
      const key = 'VF.WS.62bcb0cca5184300066f5ac7.egnKyyzZksiS5iGa';
      const result = utils.extractAPIKeyID(key);

      expect(result).to.equal('62bcb0cca5184300066f5ac7');
    });
`,
			shouldMatch: true,
			match:       `VF.WS.62bcb0cca5184300066f5ac7.egnKyyzZksiS5iGa`,
		},
		{
			name: `valid_result7_legacy`,
			data: `    it('extracts ID from a Legacy Workspace API key', () => {
      // eslint-disable-next-line no-secrets/no-secrets
      const key = 'VF.62bcb0cca5184300066f5ac7.dmC8KKO1oX8JO5az';
      const result = utils.extractAPIKeyID(key);

      expect(result).to.equal('62bcb0cca5184300066f5ac7');
    });`,
			shouldMatch: true,
			match:       `VF.62bcb0cca5184300066f5ac7.dmC8KKO1oX8JO5az`,
		},

		// False positives
		// https://github.com/ImperialCollegeLondon/voiceflow-integration-whatsapp/blob/0f3d6a5638b9acb4989d5bf8e77081cc78e9b976/README.md?plain=1#L155
		{
			name:        `invalid_result1`,
			data:        "Now, paste it in your .env file for the **VF_PROJECT_API** variable<br>\n```VF_PROJECT_API='VF.DM.62xxxxxxxxxxxxxxxxxxxxxxx'```",
			shouldMatch: false,
		},
		// https://github.com/voiceflow/api-examples/blob/c3d8ba9ee8eced7ec8d241973b1eb0284aaec212/rust/src/main.rs#L5
		{
			name:        `invalid_result2`,
			data:        `const API_KEY: &str = "YOUR_API_KEY_HERE"; // it should look like this: VF.DM.XXXXXXX.XXXXXX... keep this a secret!`,
			shouldMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("Voiceflow.FromData() error = %v", err)
				return
			}

			if test.shouldMatch {
				if len(results) == 0 {
					t.Errorf("%s: did not receive a match for '%v' when one was expected", test.name, test.data)
					return
				}
				expected := test.data
				if test.match != "" {
					expected = test.match
				}
				result := results[0]
				resultData := string(result.Raw)
				if resultData != expected {
					t.Errorf("%s: did not receive expected match.\n\texpected: '%s'\n\t  actual: '%s'", test.name, expected, resultData)
					return
				}
			} else {
				if len(results) > 0 {
					t.Errorf("%s: received a match for '%v' when one wasn't wanted", test.name, test.data)
					return
				}
			}
		})
	}
}

func TestVoiceflow_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("VOICEFLOW")
	inactiveSecret := testSecrets.MustGetField("VOICEFLOW_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a voiceflow secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Voiceflow,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a voiceflow secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Voiceflow,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
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
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a voiceflow secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Voiceflow,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a voiceflow secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Voiceflow,
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
				t.Errorf("Voiceflow.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
				t.Errorf("Voiceflow.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
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
