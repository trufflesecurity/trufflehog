package gcp

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestGCP_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
		skip  bool
	}{
		{
			name: "valid pattern",
			input: `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "GCP",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"gcp_secret": {
				"type": "service_account",
				"project_id": "my-test-project",
				"private_key_id": "abc12345def67890ghi",
				"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----\n",
				"client_email": "my-test-project@my-gcp-project.iam.gserviceaccount.com",
				"client_id": "123456789012345678901",
				"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				"token_uri": "https://oauth2.googleapis.com/token",
				"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/my-service-account%40my-gcp-project.iam.gserviceaccount.com"
			}
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`,
			want: []string{`{"type":"service_account","project_id":"my-test-project","private_key_id":"abc12345def67890ghi","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----\n","client_email":"my-test-project@my-gcp-project.iam.gserviceaccount.com","client_id":"123456789012345678901","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/my-service-account%40my-gcp-project.iam.gserviceaccount.com"}`},
		},
		{
			name: "normal file",
			input: `{
  "type": "service_account",
  "project_id": "api-5153635936162123384-123456",
  "private_key_id": "2b387b72ec1b082aa7e52189d9c43f58fb19fb48",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE/XlaMP419pkUEXAMPLE=\n-----END PRIVATE KEY-----\n",
  "client_email": "unit-test-value@api-5153635936162123384-123456.iam.gserviceaccount.com",
  "client_id": "109763165530299657612",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/unit-test-value%40api-5153635936162123384-123456.iam.gserviceaccount.com"
}`,
			want: []string{"{\"type\":\"service_account\",\"project_id\":\"api-5153635936162123384-123456\",\"private_key_id\":\"2b387b72ec1b082aa7e52189d9c43f58fb19fb48\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE/XlaMP419pkUEXAMPLE=\\n-----END PRIVATE KEY-----\\n\",\"client_email\":\"unit-test-value@api-5153635936162123384-123456.iam.gserviceaccount.com\",\"client_id\":\"109763165530299657612\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\",\"client_x509_cert_url\":\"https://www.googleapis.com/robot/v1/metadata/x509/unit-test-value%40api-5153635936162123384-123456.iam.gserviceaccount.com\"}"},
		},
		{
			name:  "escaped JSON",
			input: `{"credentials":"{\n  \"type\": \"service_account\",\n  \"project_id\": \"unit-test\",\n  \"private_key_id\": \"10f922eb17fba903dc59f7baf753976233520012\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCgyAZHbtJu1MRf\\ng9+Wg==\\n-----END PRIVATE KEY-----\\n\",\n  \"client_email\": \"fake-value@unit-test.iam.gserviceaccount.com\",\n  \"client_id\": \"123456476766156356779\",\n  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n  \"token_uri\": \"https://oauth2.googleapis.com/token\",\n  \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n  \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/fake-value%40unit-test.iam.gserviceaccount.com\"\n}\n"}`,
			want:  []string{"{\"type\":\"service_account\",\"project_id\":\"unit-test\",\"private_key_id\":\"10f922eb17fba903dc59f7baf753976233520012\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCgyAZHbtJu1MRf\\ng9+Wg==\\n-----END PRIVATE KEY-----\\n\",\"client_email\":\"fake-value@unit-test.iam.gserviceaccount.com\",\"client_id\":\"123456476766156356779\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\",\"client_x509_cert_url\":\"https://www.googleapis.com/robot/v1/metadata/x509/fake-value%40unit-test.iam.gserviceaccount.com\"}"},
		},
		{
			name: "no private_key_id (1)",
			input: `      {
  			resolve: 'gatsby-source-google-spreadsheet',
  			options: {
  				/// TODO ///
          // Find a better way to include credentials without literally displaying in the config.
          credentials: {
            client_email: "gatsby-project@gatsby-project.iam.gserviceaccount.com",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCuT6NTCf5cILhY\nQrqiah7ukgW1yzOR2brT2V1jiux77q22ljeB2XcnVivg97MWLKpPbghvV+zd7QLi\n4WQZL0f7x5W0yTs8CU6cyVNn/dWewEyWQbKifxWoJZiOhxw7cLIoZkY0Vtz9WQy3\nt0rvwMrkRpvA8dSVtgfOr2uSIAxA5vqsvl9VkT+WFy3bU1oKdUcUWGqhB2kg9wJh\nXLFdfGewt1xezEiFom2WTHx1lltQ5NURJALzo9GfelMfeBR2BPlRdrDp+vpPT1V4\nv90JO7V7yaJm5LeyOX1eKmcrQRw/gKnA9XYifdKl01sTIM4p3Rl6mJZe1iPkWVNj\nWGhW+zzZAgMBAAECggEABO85tSXVBsghV9RJwsPEzOWi1j7inpgejxU57NG3uJLs\n3vyZJSqiEiHBG7z/W5sXliiMAhTn3m9xc7lEMjdQfxrrDMNekyhDSrJzU0APDk+s\ny1sgQrPcydYIn85I2RDrZjPg/GXSGzTsZH4Cl89qHvS1v4xJA5Tz2yDBp5ETL+oe\nK3Xba1+TtvsCh14xAnx81yTFIGvjVukh3iXa8PjRdeANrw/WV/0eK6rA5wga20Ik\nsiV8C5t0rXMtF/ZMTagtQa/PL7G890T8CnbulMeYlZ1vhXTlNTMqrL9gl6Scmyuk\n0LWEWeElLHm9C+jDkdPjp+GAF7S6T7QO3r7k4tFHJQKBgQDqjmgtu0nqUqdpl5Un\nr6oUqLCYdMqCl2QjXmBEWdzXqtwo0YeBYGJHI+fc1JhI/XXAZX3AlIvaxzTuEgK6\n3T5pix51jXafFP3mR/WSWj9oFaH3MVp4V28fdnTkZjugPnEDl2vIKYMaiKQdEV0u\nqQLVHi1PT98STp1fnICew3h3/QKBgQC+Pz4qiJUTkuLP1n77K3/GzqVVnQFtPYMr\n1Ob04tDMeAnVL/yW38eP7tVHufeRMGt3A936vl+TF+c2doQLH3zsUFKF368TXsDi\nhSNsxYWeMhi/VejQkpPG7MXZj30nT3AI6YAmcwd5wwWkhGUSDeF6p/H9p89t+f/m\njpyBAB5JDQKBgFjWcxLPGuHLSGkv5mhPmkWU1r4HjiQEHwNeXWvF9WUh65zyLzaL\nQO3c5Za4Vq1egljKl+R23rmQNWXt0GbiIR9sd67iU4lRNBEiNBqoX9eWSfAMG031\nH7t07DUNm4vH2poXodUAFA3arv3rc7WWgeIiOdsOT1jpuaVa60Q2mMwpAoGBAI9d\ng1B0KrtcZpWvE3PdvOWplghlT8ztnOqr/vut7SEimHhSOCvOKUn69jieGMUN0v4W\nKPKrAcUML03ok+r56J8AjJ+cCAg10G8jW6W9V8r1/5Y4fECpJvxzM0mXCv5Tq57b\nr5nJ92k3oQnwR2YKlc9jvkWjbvp2efRZpfDEkQ4FAoGBAJLgC5YaWiFjn2EGtlGa\nKxunQ+zU/TtReRNCA9fjTdlxzH7uqHPrTTZ58TAf8VfI1T01rqY2LPXYsgxfU6ut\nbJrxof0hp00dDKldxFOl5QbvoXhF7T3Bq5RK9uFpxSOpaXvKIMjmYmACgeP1XNNq\n4ThWdWJOMDXLaJN2Mj8n3kih\n-----END PRIVATE KEY-----\n"
          },
          // Spreadsheet is here: https://docs.google.com/spreadsheets/d/...
`,
			skip: true,
		},
		{
			name: "no private_key_id (2)",
			input: `
module.exports = {
    credentials: {
        google: {
            client_email: process.env.GOOGLE_CLIENT_EMAIL || 'cloudsploit@your-project-name.iam.gserviceaccount.com',
            private_key: process.env.GOOGLE_PRIVATE_KEY || '-----BEGIN PRIVATE KEY-----\nYOUR-PRIVATE-KEY-GOES-HERE\n-----END PRIVATE KEY-----\n'
        },`,
			skip: true,
		},
		{
			name: ".env",
			input: `GOOGLE_SERVICE_ACCOUNT_EMAIL=jedicconnect@f4k3acc.iam.gserviceaccount.com
GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkVEmh423RApn2\nv262VYWKhkyf11erwQPIdQP2f+zSXDxZJwQ2vAY/ecamlYz2TnDoXTM7LghLGXXd\n1ZdcMaAX3dgQdxt36B/gRLOO8eyQwEQjvseSm3NFQjyrX9x94STmrEOWP7xR8DuZ\nhq3hFXT9knD8CW+TwG7rQn0e6mdUqz2tujptLFwo+GUZZ4vbw1Y2pU9QBiVDtA8R\nIVdpDFujLS3nxJEhKUY7WYSWr1cwJwqBNMfIq0GW+Sk8/E25qHztZVsMsvyUtIIF\nH21dGMoyc4CSDWqdgSQvEeyTi9zrlVWA4/gHyb246UlkvEdOBVKH1jiZy76atsLS\nNCtIk6A3AgMBAAECggEAHiluXm19EZj1o4mdi5AE89kUpV4ENH038Yow0QTH9hCB\n7ycvKdC3IN18LcVTWz4okS3SInGfihFBRhdXMc/V/6tzZgpGm2qalzJE9t7Gugbg\nOuNghDNOJA81TYtJ0D0L5d8GhMRsD2oVtmc28RJcJ9LCNDCTLz5p3XqUhTSnBK4h\n2ad5BHgXgCinVXZ+KgCnrm6obijcrlvTGacGXT42UsRA/AJE9Lh2t+zNQE0v6T+B\niI/DEHcq0gNU8yKQSiLsL7P1nc3sLZs7DKsLP0NH1Wd4wgupM9PnPMPAHAwye1tA\nz/hdaUbU94lPW/40rw26DwwX1rfHFavRy/JN2VH52QKBgQDl9v4XxGjgmcted01H\nXPELsfJPod9PCr6M7swUVCRzP2m1CB9efOJBd3yzFI/beQxNjhVH3tUEioHdMgzJ\nrJHB44NyYLaVDFhIcTDlyTKlEYpd7kT5xMGqbcuLRSr0/EH9Ut69+buMqvcXCo9t\nlpgfvx5PizZ6FWCzUeR/qQ5DAwKBgQC27v9UT6dpl47DYUKls1laTsN+wiaFXiuY\n39MPGwXW4AmfY2VqrVuGaGc1+ls9Am75/BkEQr9rDmuy/p+tqeOrILGMskuSzwzO\n5NJ9DbXwgU+rBkRGYP4QdY3eYlsQQJXjrYmtXi03J6NZiVLozMN5Clk6yJLjZue0\nNPMpjl8YXQKBgGfiqmrGObKtB2hHcMu6OtJTsukycRTd/7Le9aaBVG4TyYcUgkdH\nF1cHyXeE5G/7QQmQFCEBky2X/I6WW5yHrtjuFKWI9zJh/0fKipJjz9MuF1nTl6lV\nrz90liz2NC+z/YOY+jLMLGOhoDnydVTGYTaGOgUpGJUSLzsS1ayuDFlNAoGALJRz\nrrU2pBnmFaEHH+BkHwjgxWxE/O1lDH1HLwAz3Rh939TWKzgR/OBGfrYDNAv6xXr1\nEb++bDV4c4dvnF+xdsuh2Rq+JgnFIkpLLWSA+RpaMuB1FP2gDJzJNO+dJ4nFvVVW\nHuS7ehxzx2cayFbWMBIgip3EhhxWzOi2dWMXs5UCgYA6wgiuw7w/Yw+/E6VThyPz\nzAspslQJzT4CzrW1WYwyZPCKAkdxIUd31pVtfj3M8duIpFkT5QidaBY54a3A8aU6\nY3kigasNRpSEMK7/ldMkX9pgPL6LGC1mmb7oTxIJjjAN6xcKVznF756LoK9A7+m6\nNrT7PzoKmZkC7BpmKV4CdQ==\n-----END PRIVATE KEY-----\n"
`,
			skip: true,
		},
		// TODO: Create an example of these.
		// {
		//	name:  "Slack mangled email",
		//	input: ``,
		//	want:  []string{""},
		// },
		// {
		//	name:  "Empty client email",
		//	input: ``,
		//	want:  []string{""},
		// },
		// {
		//	name:  "Carets",
		//	input: ``,
		//	want:  []string{""},
		// },
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.skip {
				t.Skip()
				return
			}

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
