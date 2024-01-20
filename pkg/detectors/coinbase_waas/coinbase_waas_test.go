//go:build detectors
// +build detectors

package coinbase_waas

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestCoinbaseWaaS_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
	}{
		// True positives
		// https://github.com/coinbase/waas-client-library-go/issues/41
		{
			name:        "valid_result1",
			data:        `{ "name": "organizations/14d1742b-3575-4490-b9bc-a8a9c7e4973d/apiKeys/7473d38c-80c6-4a69-a715-1ea8fd950f6f", "principal": "8feb538e-137b-5864-b12a-7c75b60fa20a", "principalType": "USER", "publicKey": "-----BEGIN EC PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzR0G+CW0uVJFrpLUELqB+DlsmGmO\nA03Az8Fpv7azpgjAy87ibgQTThaQy1C1BccbCDkPoEs6mOnDkOebkybAKQ==\n-----END EC PUBLIC KEY-----\n", "privateKey": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBddyynZ9Ya7op1B9nu1Dxyc1T6xLy72t45J2Smv9oXNoAoGCCqGSM49\nAwEHoUQDQgAEzR0G+CW0uVJFrpLUELqB+DlsmGmOA03Az8Fpv7azpgjAy87ibgQT\nThaQy1C1BccbCDkPoEs6mOnDkOebkybAKQ==\n-----END EC PRIVATE KEY-----\n", "createTime": "2023-08-19T12:29:08.938421763Z", "projectId": "5970e137-9c3d-4adc-b65d-58d33af2432d" }`,
			shouldMatch: true,
			match:       "organizations/14d1742b-3575-4490-b9bc-a8a9c7e4973d/apiKeys/7473d38c-80c6-4a69-a715-1ea8fd950f6f:-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBddyynZ9Ya7op1B9nu1Dxyc1T6xLy72t45J2Smv9oXNoAoGCCqGSM49\nAwEHoUQDQgAEzR0G+CW0uVJFrpLUELqB+DlsmGmOA03Az8Fpv7azpgjAy87ibgQT\nThaQy1C1BccbCDkPoEs6mOnDkOebkybAKQ==\n-----END EC PRIVATE KEY-----\n",
		},
		// https://github.com/coinbase/waas-client-library-go/pull/32#issuecomment-1666415017
		{
			name: "valid_result2_name_slashes",
			data: `{
				"name": "organizations\/d3f266dc-0d36-4cd0-91c3-e3a292b0b4b3\/apiKeys\/032c4fdf-d763-4b0c-9ed3-ff41a873bcc8",
				"principal": "5d5c9f00-3224-52a7-a1f7-9e6ce3ada40c",
				"principalType": "USER",
				"publicKey": "-----BEGIN EC PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAjw43hwOqS2PF4gAFbhoxIJqCHAP\niqLdg5GFVn9QAS/0oY4/fJGrCn9rpQGOvHxHf1mtQ6j4bIWN1AtHvA/3uw==\n-----END EC PUBLIC KEY-----\n",
				"privateKey": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFkA1kU4DlNu36wTTHycWy6n1rsUH0UT8mfAKNtOukXHoAoGCCqGSM49\nAwEHoUQDQgAEAjw43hwOqS2PF4gAFbhoxIJqCHAPiqLdg5GFVn9QAS/0oY4/fJGr\nCn9rpQGOvHxHf1mtQ6j4bIWN1AtHvA/3uw==\n-----END EC PRIVATE KEY-----\n",
				"createTime": "2023-08-05T06:34:40.265235553Z",
				"projectId": "64b3f391-c69d-4c59-91a2-75816c1a0738"
				}`,
			shouldMatch: true,
			match:       "organizations/d3f266dc-0d36-4cd0-91c3-e3a292b0b4b3/apiKeys/032c4fdf-d763-4b0c-9ed3-ff41a873bcc8:-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFkA1kU4DlNu36wTTHycWy6n1rsUH0UT8mfAKNtOukXHoAoGCCqGSM49\nAwEHoUQDQgAEAjw43hwOqS2PF4gAFbhoxIJqCHAPiqLdg5GFVn9QAS/0oY4/fJGr\nCn9rpQGOvHxHf1mtQ6j4bIWN1AtHvA/3uw==\n-----END EC PRIVATE KEY-----\n",
		},
		{
			name: "valid_result3",
			data: `name: "organizations/7eead2d5-fa48-4423-8f40-c70d8ce398ae/apiKeys/7b9516b6-d82e-44e8-bed5-89b160452ed9",
		description: "principal": "775fb863-004f-5412-8e4c-e9449c612563" and install dependencies
		
		runs:    "principalType": "USER",
		 using: composite
		 steps:"publicKey": "-----BEGIN EC PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvHsvI08kox+n/8wSMFwCbK5hEf5b\n/g82Lmz3HpATKFmrICcOBX2lRHo99JWRrupmjUGxnD8i4sj4mZafTEokhA==\n-----END EC PUBLIC KEY-----\n",
		   - name: Setup Node.js
		     uses: actions/setup-node@v3
		     with: "privateKey": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKOQ7lvGL0EiUzZ23pmH/NBPRwVV8yZsqofds5bSR9qFoAoGCCqGSM49\nAwEHoUQDQgAEvHsvI08kox+n/8wSMFwCbK5hEf5b/g82Lmz3HpATKFmrICcOBX2l\nRHo99JWRrupmjUGxnD8i4sj4mZafTEokhA==\n-----END EC PRIVATE KEY-----\n",
		       node-version-file: .nvmrc
		
		   - name: Cache dependencies`,
			shouldMatch: true,
			match:       "organizations/7eead2d5-fa48-4423-8f40-c70d8ce398ae/apiKeys/7b9516b6-d82e-44e8-bed5-89b160452ed9:-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKOQ7lvGL0EiUzZ23pmH/NBPRwVV8yZsqofds5bSR9qFoAoGCCqGSM49\nAwEHoUQDQgAEvHsvI08kox+n/8wSMFwCbK5hEf5b/g82Lmz3HpATKFmrICcOBX2l\nRHo99JWRrupmjUGxnD8i4sj4mZafTEokhA==\n-----END EC PRIVATE KEY-----\n",
		},
		{
			name: "valid_result_ecdsa",
			data: `{
    "name": "organizations/7eead2d5-fa48-4423-8f40-c70d8ce398ae/apiKeys/7b9516b6-d82e-44e8-bed5-89b160452ed9",
    "privateKey": "-----BEGIN ECDSA PRIVATE KEY-----\nMHcCAQEEINQdZMbF2r07KF0mxfLYt9Y1PNaC0C6UpZ31MxD4NEE8oAoGCCqGSM49\nAwEHoUQDQgAEeRFgMrQEHI/APWaziRH90jN7EozjdbPVxvzc1F4zqWTeCtLASwqA\nqnMugYX2epqsFhGn82xNXu2NwgORc6embQ==\n-----END ECDSA PRIVATE KEY-----\n"
}`,
			shouldMatch: true,
			match:       "organizations/7eead2d5-fa48-4423-8f40-c70d8ce398ae/apiKeys/7b9516b6-d82e-44e8-bed5-89b160452ed9:-----BEGIN ECDSA PRIVATE KEY-----\nMHcCAQEEINQdZMbF2r07KF0mxfLYt9Y1PNaC0C6UpZ31MxD4NEE8oAoGCCqGSM49\nAwEHoUQDQgAEeRFgMrQEHI/APWaziRH90jN7EozjdbPVxvzc1F4zqWTeCtLASwqA\nqnMugYX2epqsFhGn82xNXu2NwgORc6embQ==\n-----END ECDSA PRIVATE KEY-----\n",
		},
		// TODO: Is it worth supporting case-insensitve headers?
		// https://github.com/coinbase/waas-sdk-react-native/blob/bbaf597e73d02ecaf64161061e71b85d9eeeb9d6/example/src/.coinbase_cloud_api_key.json#L4
		//		{
		//			name: "valid_result_case_insensitive",
		//			data: `{
		//    "name": "organizations/7eead2d5-fa48-4423-8f40-c70d8ce398ae/apiKeys/7b9516b6-d82e-44e8-bed5-89b160452ed9",
		//    "privateKey": "-----BEGIN ECDSA private key-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8id7yCfmNp0ppczu\nDhjB1pesdDB6Uwuz6KxARrenNfyhRANCAASI6DBntdr+XSOaK55J++x8ORuDxn81\nENa0RmGFjTwu4vQcWcx5rrIWNh6b7FPxy6mrZl0n3rswEtZmUci8Y5HX\n-----END ECDSA PRIVATE KEY-----\n"
		//}`,
		//			shouldMatch: true,
		//			match:       "organizations/7eegad2d5-fa48-4423-8f40-c70d8ce398ae/apiKeys/7b9516b6-d82e-44e8-bed5-89b160452ed9:-----BEGIN ECDSA PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8id7yCfmNp0ppczu\nDhjB1pesdDB6Uwuz6KxARrenNfyhRANCAASI6DBntdr+XSOaK55J++x8ORuDxn81\nENa0RmGFjTwu4vQcWcx5rrIWNh6b7FPxy6mrZl0n3rswEtZmUci8Y5HX\n-----END ECDSA PRIVATE KEY-----\n",
		//		},

		// False positives
		// https://github.com/coinbase/waas-client-library-go/blob/main/example.go
		{
			name: `invalid_key_name1`,
			data: `const (
	// apiKeyName is the name of the API Key to use. Fill this out before running the main function.
	apiKeyName = "organizations/my-organization/apiKeys/my-api-key"

	// privKeyTemplate is the private key of the API Key to use. Fill this out before running the main function.
	privKeyTemplate = "-----BEGIN EC PRIVATE KEY-----\nmy-private-key\n-----END EC PRIVATE KEY-----\n"
)`,
			shouldMatch: false,
		},
		// https://github.com/coinbase/waas-sdk-react-native/blob/bbaf597e73d02ecaf64161061e71b85d9eeeb9d6/example/src/.coinbase_cloud_api_key.json#L4
		{
			name: `invalid_key_name2`,
			data: `{
    "name": "organizations/organizationID/apiKeys/apiKeyName",
    "privateKey": "-----BEGIN ECDSA Private Key-----ExamplePrivateKey-----END ECDSA Private Key-----\n"
}`,
		},
		{
			name: `invalid_private_key`,
			data: `{ "name": "organizations/14d1742b-3575-4490-b9bc-a8a9c7e4973d/apiKeys/7473d38c-80c6-4a69-a715-1ea8fd950f6f", "principal": "8feb538e-137b-5864-b12a-7c75b60fa20a", "principalType": "USER", "publicKey": "-----BEGIN EC PUBLIC KEY-----\ninvalid\n-----END EC PUBLIC KEY-----\n", "privateKey": "-----BEGIN EC PRIVATE KEY-----\ninvalid\n-----END EC PRIVATE KEY-----\n", "createTime": "2023-08-19T12:29:08.938421763Z", "projectId": "5970e137-9c3d-4adc-b65d-58d33af2432d" }`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("CoinbaseWaaS.FromData() error = %v", err)
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
				resultData := string(result.RawV2)
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

func TestCoinbaseWaaS_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secretb64 := testSecrets.MustGetField("COINBASE_WAAS")
	secretB, err := base64.StdEncoding.DecodeString(secretb64)
	if err != nil {
		t.Fatalf("could not decode secret: %s", err)
	}
	secret := string(secretB)

	inactiveSecretb64 := testSecrets.MustGetField("COINBASE_WAAS_INACTIVE")
	inactiveSecretB, err := base64.StdEncoding.DecodeString(inactiveSecretb64)
	if err != nil {
		t.Fatalf("could not decode secret: %s", err)
	}
	inactiveSecret := string(inactiveSecretB)

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
				data:   []byte(fmt.Sprintf("You can find a coinbase_waas secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_CoinbaseWaaS,
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
				data:   []byte(fmt.Sprintf("You can find a coinbase_waas secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_CoinbaseWaaS,
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
				data:   []byte(fmt.Sprintf("You can find a coinbase_waas secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_CoinbaseWaaS,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a coinbase_waas secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_CoinbaseWaaS,
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
				t.Errorf("Coinbasewaas.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Coinbasewaas.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
