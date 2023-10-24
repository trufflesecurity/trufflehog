//go:build detectors
// +build detectors

package azure

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestAzure_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
		matches     []string
	}{
		// True positives
		{
			name: `valid_appid`,
			data: `Creating 'Contributor' role assignment under scope '/subscriptions/52cc768e-b7a8-473a-adcc-68779a7d7bae'
The output includes credentials that you must protect. Be sure that you do not include these credentials in your code or check the credentials into your source control. For more information, see https://aka.ms/azadsp-cli
{
  "appId": "4ba50db1-3f3f-4521-8a9a-1be0864d922a",
  "displayName": "azure-cli-2022-12-02-15-40-24",
  "password": "UVq8Q~7VPj9hIVYQ6QCtmCfUyNOTLoaIsXe8IdwS",
  "tenant": "cea1e271-5c0b-4fd7-b9e7-fb316d41d83b"
}`,
			shouldMatch: true,
			match:       `4ba50db1-3f3f-4521-8a9a-1be0864d922a:UVq8Q~7VPj9hIVYQ6QCtmCfUyNOTLoaIsXe8IdwS (cea1e271-5c0b-4fd7-b9e7-fb316d41d83b)`,
		},
		{
			name: `valid_application_id`,
			data: `# Login using Service Principal
$ApplicationId = "1e002bca-c6e2-446e-a29e-a221909fe8aa"
$SecuredPassword = ConvertTo-SecureString -String "WJq7Q~ACTBEedBvD22NOxDoOhA5G5GZ68FlkR" -AsPlainText -Force
$TenantId = "967866e4-0a2c-4bc9-8cc8-8db0879e0ffe"
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecuredPassword
Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential`,
			shouldMatch: true,
			match:       `1e002bca-c6e2-446e-a29e-a221909fe8aa:WJq7Q~ACTBEedBvD22NOxDoOhA5G5GZ68FlkR (967866e4-0a2c-4bc9-8cc8-8db0879e0ffe)`,
		},
		{
			name:        `valid_az_cli_login`,
			data:        `az login --service-principal --username "21e144ac-532d-49ad-ba15-1c40694ce8b1" --password ".df8Q~oEyHYd5_BmELmY~zmVXul8~OU_fCDnNkpe" --tenant "2ce99e96-b41b-47a0-b37c-16a22bceb8c0"`,
			shouldMatch: true,
			match:       `21e144ac-532d-49ad-ba15-1c40694ce8b1:.df8Q~oEyHYd5_BmELmY~zmVXul8~OU_fCDnNkpe (2ce99e96-b41b-47a0-b37c-16a22bceb8c0)`,
		},
		{
			name: `valid_dotenv_file`,
			data: `export AUTH_SCOPES=openid
export CLIENT_ID=3b835dac-1798-447d-9be0-ca8b270931b4
export TENANT_ID=32238a1a-16c5-4f57-8cb2-6a5b521e5ed8
export CLIENT_SECRET=6LB8Q~ZyEDCDwI_oJvdVkJmBgFK1MHg-p7sEsa9v
`,
			shouldMatch: true,
			match:       `3b835dac-1798-447d-9be0-ca8b270931b4:6LB8Q~ZyEDCDwI_oJvdVkJmBgFK1MHg-p7sEsa9v (32238a1a-16c5-4f57-8cb2-6a5b521e5ed8)`,
		},
		{
			name: `valid_hcl`,
			data: `location = "eastus"
subscription_id = "47ab1364-000d-4a53-838d-1537b1e3b49f"
tenant_id = "57aabdfc-6ce0-4828-94a2-9abe277892ec"
client_id = "89d5bd08-0d51-42cd-8eab-382c3ce11199"
client_secret = "iVq8Q~7VPT9hIVYQ6QCtmCfUyNOTL-aIsze8IdwS"`,
			shouldMatch: true,
			match:       `89d5bd08-0d51-42cd-8eab-382c3ce11199:iVq8Q~7VPT9hIVYQ6QCtmCfUyNOTL-aIsze8IdwS (57aabdfc-6ce0-4828-94a2-9abe277892ec)`,
		},
		{
			name: `valid_java`,
			data: `@TestPropertySource(properties = {
        "cas.authn.azure-active-directory.client-id=532c556b-1260-483f-9695-68d087fcd965",
        "cas.authn.azure-active-directory.client-secret=R058Q~NbOEInGNcAEdxHGWJ3QkSojVTLP1fuLcg-",
        "cas.authn.azure-active-directory.login-url=https://login.microsoftonline.com/common/",
        "cas.authn.azure-active-directory.tenant=8e439f30-da7a-482c-bd23-e45d0a732000"
    })
    @Nested
    class ConfidentialClientTests extends BaseAzureActiveDirectoryTests {`,
			shouldMatch: true,
			match:       `532c556b-1260-483f-9695-68d087fcd965:R058Q~NbOEInGNcAEdxHGWJ3QkSojVTLP1fuLcg- (8e439f30-da7a-482c-bd23-e45d0a732000)`,
		},
		{
			name: `valid_js`,
			data: `export const msalConfig = {
  auth: {
    clientId: '82c54108-535c-40b2-87dc-2db599df3810',
    clientSecret: 'R7l8Q~r-BCz3cPBHDl6jQrcM3xSVIFc4eqaxBaHn',
    authority: 'https://login.microsoftonline.com/7bb339cb-e94c-4a85-884c-48ebd9bb28c3',
    redirectUri: 'http://localhost:8080/landing'
  },`,
			shouldMatch: true,
			match:       `82c54108-535c-40b2-87dc-2db599df3810:R7l8Q~r-BCz3cPBHDl6jQrcM3xSVIFc4eqaxBaHn (7bb339cb-e94c-4a85-884c-48ebd9bb28c3)`,
		},
		{
			name: `valid_json1`,
			data: `
  "AZURE_AUTHORITY": "https://login.microsoftonline.com/2060dc95-ebc4-43cb-bf8b-5ad1890ab92e",
  "AZURE_CLIENT_ID": "54092b2f-46c8-4202-8d5c-212afb244b22",
  "AZURE_CLIENT_SECRET": "9Rm8Q~0rg4K8uO5IGmqUGJxXkLjjg8OpJGBo-cvH",
  "AZURE_SCOPES": ["api://84ded6b7-a5f0-493b-927f-79f4b961d2f1/.default"],`,
			shouldMatch: true,
			match:       `54092b2f-46c8-4202-8d5c-212afb244b22:9Rm8Q~0rg4K8uO5IGmqUGJxXkLjjg8OpJGBo-cvH (2060dc95-ebc4-43cb-bf8b-5ad1890ab92e)`,
		},
		{
			name: `valid_json2`,
			data: `  },
  "AzureTokenConfig": {
    "client_id": "adf16a53-1b52-4cde-9d2d-d2715bfc924f",
    "scope": "api://a6b39412-b6af-4add-b6a6-f9ceb539c331/.default",
    "client_secret": "zOn7Q~8LaiLhxFWMq745vvjT3mPp5gCrGuOUG"
  },
  "HttpClientConfiguration": {
    "AzureTokenAPI": {
      "Name": "AzureTokenAPI",
      "DestinationUri": "https://login.microsoftonline.com/2fba5566-20ad-443f-8c38-1beb6e7deec7/oauth2/v2.0/token",
      "RequestTimeout": "00:00:08",`,
			shouldMatch: true,
			match:       `adf16a53-1b52-4cde-9d2d-d2715bfc924f:zOn7Q~8LaiLhxFWMq745vvjT3mPp5gCrGuOUG (2fba5566-20ad-443f-8c38-1beb6e7deec7)`,
		},
		{
			name: `valid_microsoftonline_tenantid1`,
			data: `  # token,errors = get_token(client_id='a872ea07-514e-4d5c-bf72-912bd19297ce',
        #                   client_secret='GTq8Q~Dh_xQfYJwzEEvsg-j16IdfWkiA6UPOea8S',
        #                   token_endpoint='https://login.microsoftonline.com/f6f6b007-2b19-4a04-96f6-2ef5c133e91d/oauth2/v2.0/token',
        #                   scope='e8a93707-5291-4b91-bdf5-c85eead08194/.default'`,
			shouldMatch: true,
			match:       `a872ea07-514e-4d5c-bf72-912bd19297ce:GTq8Q~Dh_xQfYJwzEEvsg-j16IdfWkiA6UPOea8S (f6f6b007-2b19-4a04-96f6-2ef5c133e91d)`,
		},
		{
			name: `valid_microsoftonline_tenantid2`,
			data: `  "AZURE_AUTHORITY": "https://login.microsoftonline.com/29d7baf0-445a-4bde-be2b-ca95f86ee334",
  "AZURE_CLIENT_ID": "a54e584d-6fc4-464c-8479-dc67b5d87ab9",
  "AZURE_CLIENT_SECRET": "9Rv7Q~0rg4K8uOVIGmqUGJxXkLjjQ8OpJGBo2c-H",`,
			shouldMatch: true,
			match:       `a54e584d-6fc4-464c-8479-dc67b5d87ab9:9Rv7Q~0rg4K8uOVIGmqUGJxXkLjjQ8OpJGBo2c-H (29d7baf0-445a-4bde-be2b-ca95f86ee334)`,
		},
		{
			name: `valid_properties`,
			data: `# =============================================================================================================
# AAD client application properties
# =============================================================================================================
aad.authority=https://login.microsoftonline.com/5efe3911-ebe9-41a7-bad5-4a0aef62bfc7/oauth2/v2.0/authorize
aad.clientId=e632140d-53a8-40e5-a097-2940383a1f0f
aad.oboDefaultScope=read
aad.secretKey=M0W8Q~kNey10py3244AzCOJv_o4or8g-ACJrfdko
`,
			shouldMatch: true,
			match:       `e632140d-53a8-40e5-a097-2940383a1f0f:M0W8Q~kNey10py3244AzCOJv_o4or8g-ACJrfdko (5efe3911-ebe9-41a7-bad5-4a0aef62bfc7)`,
		},
		{
			name: `valid_no_tenant1`,
			data: `string azureAdDomain = "570954d0-b54b-4e22-8488-01f6da72b771";
                string loginUrl = $"https://login.microsoftonline.com/{azureAdDomain}/oauth2/token";
                string clientId = "b9cbc91c-c890-4824-a487-91611bb0615a";
                string clientSecret = "JUn8Q~dEOhjcWwKOm~V8jU2ZPHObsuSRhGw2Oazb";`,
			shouldMatch: true,
			match:       `b9cbc91c-c890-4824-a487-91611bb0615a:JUn8Q~dEOhjcWwKOm~V8jU2ZPHObsuSRhGw2Oazb`,
		},
		{
			name: `valid_no_tenant2`,
			data: `{
	"onedrive-international": {
		"client_id": "902aeb6d-29c7-4f6e-849d-4b933117e320",
		"client_secret": "0WA8Q~sZkZFZKv50ryP4ux~.fpVtbHw7BuTZmbQB",
		"authority": "https://login.microsoftonline.com/common",
		"token_endpoint": "/oauth2/v2.0/token",
		"authorize_endpoint": "/oauth2/v2.0/authorize",
		"scopes": "offline_access Files.ReadWrite.All User.Read",
		"redirect_uri": "http://localhost",
		"api_uri": "https://graph.microsoft.com/v1.0"
	}
}`,
			shouldMatch: true,
			match:       `902aeb6d-29c7-4f6e-849d-4b933117e320:0WA8Q~sZkZFZKv50ryP4ux~.fpVtbHw7BuTZmbQB`,
		},
		{
			name: `valid_yaml1`,
			data: `azure:
      active-directory:
        enabled: true
        profile:
          tenant-id: c32654ed-6931-4bae-bb23-a8b9e420e0f4
        credential:
          client-id: 9b118c30-94c9-48b9-92e9-d7b00ba153f0
          client-secret: 3bL8Q~F9mPSWiDihY0NIpcQMAWoUoQ.c-seMvc0_
`,
			shouldMatch: true,
			match:       `9b118c30-94c9-48b9-92e9-d7b00ba153f0:3bL8Q~F9mPSWiDihY0NIpcQMAWoUoQ.c-seMvc0_ (c32654ed-6931-4bae-bb23-a8b9e420e0f4)`,
		},
		{
			name: `valid_yaml2`,
			data: `eod:
  file:
    folder-location: test
    client-id: ${vcap.services.user-authentication-service.credentials.clientid:efba6df1-0547-4448-9dd1-b9506af36cfb}
    client-secret: ${vcap.services.user-authentication-service.credentials.clientsecret:WX-8Q~tMrOdFpbDjWvN_8j_054qFpXh5bOz-vbVP}
    tenant-id: ${vcap.services.user-authentication-service.credentials.tenantid:317fb200-a693-4062-a4fb-9d131fcd2d3c}
`,
			shouldMatch: true,
			match:       `efba6df1-0547-4448-9dd1-b9506af36cfb:WX-8Q~tMrOdFpbDjWvN_8j_054qFpXh5bOz-vbVP (317fb200-a693-4062-a4fb-9d131fcd2d3c)`,
		},
		{
			name: `valid_yaml3`,
			data: `  clientId: "41524b74-8543-4352-ae3a-757aebc4fef4"
  clientSecret: "A.f8Q~AGdKmOjwNtAG.jH5IScCRnZFm8QCB-v-_d"
  aadTenantId: "012c156f-8de0-4454-b6c1-bf331d4c4008"`,
			shouldMatch: true,
			match:       `41524b74-8543-4352-ae3a-757aebc4fef4:A.f8Q~AGdKmOjwNtAG.jH5IScCRnZFm8QCB-v-_d (012c156f-8de0-4454-b6c1-bf331d4c4008)`,
		},
		{
			name: `valid_yaml4`,
			data: `spring:
  security:
    oauth2:
      client:
        provider:
          azure:
            issuer-uri: https://login.microsoftonline.com/3d8df00b-2bea-4d27-8b9d-1386f4f4918c/v2.0
            user-name-attribute: name
        registration:
          azure-dev:
            provider: azure
            #client-id: "0704100e-7e76-4e62-bfb6-70bfd33906e2"
            #client-secret: "fo28Q~-aLbmQvonnZtzbgtSiqYstmBWEmGPAodmx"
            client-id: your-client-id
            client-secret: your-secret-id
`,
			shouldMatch: true,
			match:       `0704100e-7e76-4e62-bfb6-70bfd33906e2:fo28Q~-aLbmQvonnZtzbgtSiqYstmBWEmGPAodmx (3d8df00b-2bea-4d27-8b9d-1386f4f4918c)`,
		},
		{
			name: `valid_multiple_tenants`,
			data: `azure.clientId=1334b9cd-6b8a-4467-ac63-10799cf02dac
azure.scope=https://graph.microsoft.com/.default
#azure.clientSecret=lQf8Q~8xe~hgFRkFjt5tNkd5uaJQmZc9OuIA~ajQ
azure.clientSecret=E1W8Q~6_0pesc5qTFCeI_WJcvqZmgIJ-4EpPVbef
azure.grantType=client_credentials
#azure.tanentId=23b87499-6c51-4537-83c5-65b9fd4bec0d
azure.tanentId=029e3b51-60dd-47aa-81ad-3c15b389db86`,
			shouldMatch: true,
			matches:     []string{`1334b9cd-6b8a-4467-ac63-10799cf02dac:lQf8Q~8xe~hgFRkFjt5tNkd5uaJQmZc9OuIA~ajQ`, `1334b9cd-6b8a-4467-ac63-10799cf02dac:E1W8Q~6_0pesc5qTFCeI_WJcvqZmgIJ-4EpPVbef`},
		},
		{
			name: `valid_multiple_clientids`,
			data: `azure.clientId=1334b9cd-6b8a-4467-ac63-10799cf02dac
#azure.clientId=bafe0126-03eb-4917-b3ff-4601c4e8f12f
azure.scope=https://graph.microsoft.com/.default
#azure.clientSecret=lQf8Q~8xe~hgFRkFjt5tNkd5uaJQmZc9OuIA~ajQ
azure.clientSecret=E1W8Q~6_0pesc5qTFCeI_WJcvqZmgIJ-4EpPVbef
azure.grantType=client_credentials
#azure.tanentId=23b87499-6c51-4537-83c5-65b9fd4bec0d
azure.tanentId=029e3b51-60dd-47aa-81ad-3c15b389db86`,
			shouldMatch: true,
			matches:     []string{`lQf8Q~8xe~hgFRkFjt5tNkd5uaJQmZc9OuIA~ajQ`, `E1W8Q~6_0pesc5qTFCeI_WJcvqZmgIJ-4EpPVbef`},
		},
		{
			name: `valid_typo_tenant`,
			data: `azure.clientId=1334b9cd-6b8a-4467-ac63-10799cf02dac
azure.scope=https://graph.microsoft.com/.default
azure.clientSecret=E1W8Q~6_0pesc5qTFCeI_WJcvqZmgIJ-4EpPVbef
azure.grantType=client_credentials
azure.tanentId=029e3b51-60dd-47aa-81ad-3c15b389db86`,
			shouldMatch: true,
			match:       `1334b9cd-6b8a-4467-ac63-10799cf02dac:E1W8Q~6_0pesc5qTFCeI_WJcvqZmgIJ-4EpPVbef (029e3b51-60dd-47aa-81ad-3c15b389db86)`,
		},
		//{
		//	name:        ``,
		//	data:        ``,
		//	shouldMatch: true,
		//	match:       ``,
		//},

		// False positives
		// TODO: Is it better to return just the secret, or return nothing at all?
		{
			name: `invalid_placeholders`,
			data: `azure:
      active-directory:
        enabled: true
        profile:
          tenant-id: 11111111-1111-1111-1111-111111111111
        credential:
          client-id: 00000000-0000-0000-0000-000000000000
          client-secret: 3bs8Q~F9mPSWiDihY0NIpcQjAWoUoQ.c-seM-c0_`,
			shouldMatch: true,
			match:       `3bs8Q~F9mPSWiDihY0NIpcQjAWoUoQ.c-seM-c0_`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("Azure.FromData() error = %v", err)
				return
			}

			if test.shouldMatch {
				if len(results) == 0 {
					t.Errorf("%s: did not receive a match for '%v' when one was expected", test.name, test.data)
					return
				} else if len(results) == 1 {
					expected := test.match
					result := results[0]
					var actual string
					if len(result.RawV2) > 0 {
						actual = string(result.RawV2)
					} else {
						actual = string(result.Raw)
					}
					if expected != actual {
						t.Errorf("%s: did not receive expected match.\n\texpected: '%s'\n\t  actual: '%s'", test.name, expected, actual)
						return
					}
				} else {
					expected := make(map[string]bool)
					for _, v := range test.matches {
						expected[v] = true
					}

					actual := make(map[string]bool)
					for _, result := range results {
						if len(result.RawV2) > 0 {
							actual[string(result.RawV2)] = true
						} else {
							actual[string(result.Raw)] = true
						}
					}

					if !reflect.DeepEqual(expected, actual) {
						t.Errorf("%s: did not receive expected match.\n\texpected: '%v'\n\t  actual: '%v'", test.name, expected, actual)
						return
					}
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

func TestAzure_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("AZURE_SECRET")
	secretInactive := testSecrets.MustGetField("AZURE_INACTIVE")
	id := testSecrets.MustGetField("AZURE_ID")
	tenantId := testSecrets.MustGetField("AZURE_TENANT_ID")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		s       Scanner
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(`
				tenant_id=%s
				client_id=%s
				client_secret=%s
				client_secret=%s
				`, tenantId, id, secretInactive, secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Azure,
					Redacted:     id,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(`
				tenant_id=%s
				client_id=%s
				client_secret=%s
				`, tenantId, id, secretInactive)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Azure,
					Redacted:     id,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
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
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Azure.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Azure.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}
