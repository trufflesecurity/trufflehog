package azure_entra

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type testCase struct {
	Input    string
	Expected map[string]struct{}
}

func runPatTest(t *testing.T, tests map[string]testCase, matchFunc func(data string) map[string]struct{}) {
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			matches := matchFunc(test.Input)
			if len(matches) == 0 {
				if len(test.Expected) != 0 {
					t.Fatalf("no matches found, expected: %v", test.Expected)
					return
				} else {
					return
				}
			}

			if diff := cmp.Diff(test.Expected, matches); diff != "" {
				t.Errorf("expected: %s, actual: %s", test.Expected, matches)
				return
			}
		})
	}
}

func Test_FindTenantIdMatches(t *testing.T) {
	cases := map[string]testCase{
		// Tenant ID
		"audience": {
			Input: `az offazure hyperv site create --location "eastus" --service-principal-identity-details \
	application-id="cbcfc473-97da-45dd-8a00-3612d1ddf35a" \
	audience="https://bced5192-08c4-4470-9a94-666fea59efb07/aadapp" `,
			Expected: map[string]struct{}{
				"bced5192-08c4-4470-9a94-666fea59efb0": {},
			},
		},
		"tenant": {
			Input: `        "cas.authn.azure-active-directory.login-url=https://login.microsoftonline.com/common/",
        "cas.authn.azure-active-directory.tenant=8e439f30-da7a-482c-bd23-e45d0a732000"`,
			Expected: map[string]struct{}{
				"8e439f30-da7a-482c-bd23-e45d0a732000": {},
			},
		},
		"tanentId": {
			Input: `azure.grantType=client_credentials
azure.tanentId=029e3b51-60dd-47aa-81ad-3c15b389db86`,
			Expected: map[string]struct{}{
				"029e3b51-60dd-47aa-81ad-3c15b389db86": {},
			},
		},
		"tenantid": {
			Input: ` file:
    folder-location: test
    tenantid: ${vcap.services.user-authentication-service.credentials.tenantid:317fb200-a693-4062-a4fb-9d131fcd2d3c}`,
			Expected: map[string]struct{}{
				"317fb200-a693-4062-a4fb-9d131fcd2d3c": {},
			},
		},
		"tenant id": {
			Input: `1. Enter the tenant id "2ce99e96-b41b-47a0-b37c-16a22bceb8c0"`,
			Expected: map[string]struct{}{
				"2ce99e96-b41b-47a0-b37c-16a22bceb8c0": {},
			},
		},
		"tenant_id": {
			Input: `location = "eastus"
subscription_id = "47ab1364-000d-4a53-838d-1537b1e3b49f"
tenant_id = "57aabdfc-6ce0-4828-94a2-9abe277892ec"`,
			Expected: map[string]struct{}{
				"57aabdfc-6ce0-4828-94a2-9abe277892ec": {},
			},
		},
		"tenant-id": {
			Input: `      active-directory:
        enabled: true
        profile:
          tenant-id: c32654ed-6931-4bae-bb23-a8b9e420e0f4
        credential:`,
			Expected: map[string]struct{}{
				"c32654ed-6931-4bae-bb23-a8b9e420e0f4": {},
			},
		},
		"tid": {
			Input: ` "sub": "jIzit1WEdXqAH9KZXz-e-UcqsVa1pyPoh-2hw3xjEO4",
  "tenant_region_scope": "AS",
  "tid": "974fde14-c3a4-481b-9b03-cfce18213a07",
  "uti": "2Y26RWHsWEiqhD2vi_PFAg",`,
			Expected: map[string]struct{}{
				"974fde14-c3a4-481b-9b03-cfce18213a07": {},
			},
		},
		"login.microsoftonline.com": {
			Input: `  auth: {
    authority: 'https://login.microsoftonline.com/7bb339cb-e94c-4a85-884c-48ebd9bb28c3',
    redirectUri: 'http://localhost:8080/landing'
`,
			Expected: map[string]struct{}{
				"7bb339cb-e94c-4a85-884c-48ebd9bb28c3": {},
			},
		},
		"login.windows.net": {
			Input: `az offazure hyperv site create --location "eastus" --service-principal-identity-details aad-authority="https://login.windows.net/7bb339cb-e94c-4a85-884c-48ebd9bb28c3" application-id="e9f013df-2a2a-4871-b766-e79867f30348" \'`,
			Expected: map[string]struct{}{
				"7bb339cb-e94c-4a85-884c-48ebd9bb28c3": {},
			},
		},
		"sts.windows.net": {
			Input: `{
  "aud": "00000003-0000-0000-c000-000000000000",
  "iss": "https://sts.windows.net/974fde14-c3a4-481b-9b03-cfce182c3a07/",
  "iat": 1641799220,`,
			Expected: map[string]struct{}{
				"974fde14-c3a4-481b-9b03-cfce182c3a07": {},
			},
		},
		"x-anchor-mailbox": {
			// The tenantID can be encoded in this parameter.
			// https://github.com/AzureAD/microsoft-authentication-library-for-python/blob/95a63a7fe97d91b99979e5bf78e03f6acf40a286/msal/application.py#L185-L186
			// https://github.com/silverhack/monkey365/blob/b3f43c4a2d014fcc3aae0a4103c8f2610fbb4980/core/utils/Get-MonkeySecCompBackendUri.ps1#L70
			Input: `      User-Agent:
      - python-requests/2.31.0
      X-AnchorMailbox:
        - Oid:2b9b0cb5-d707-42e3-9504-d9b76ac7bec5@86843c34-863b-44d3-bb14-4f14e7c0564d
      x-client-current-telemetry:
        - 4|84,3|`,
			Expected: map[string]struct{}{
				"86843c34-863b-44d3-bb14-4f14e7c0564d": {},
			},
		},

		// Tenant onmicrosoft.com
		"onmicrosoft tenant": {
			Input: `  "oid": "7be15f3a-d9b5-4080-ba37-95aa2e3d244e",
  "platf": "3",
  "puid": "10032001170600C8",
  "scp": "Files.Read Files.Read.All Files.Read.Selected Files.ReadWrite Files.ReadWrite.All Files.ReadWrite.AppFolder Files.ReadWrite.Selected profile User.Export.All User.Invite.All User.ManageIdentities.All User.Read User.Read.All User.ReadBasic.All openid email",
  "signin_state": [
    "kmsi"
  ],
  "sub": "jIzit1WEdXqAH9KZXz-e-UcqsVa1pyPoh-2hw3xjEO4",
  "tenant_region_scope": "AS",
  "unique_name": "ben@xhoaxiuqng.onmicrosoft.com",
  "uti": "2Y26RWHsWEiqhD2vi_PFAg",
  "ver": "1.0",
  "wids": [
    "62e90394-69f5-4237-9190-012177145e10",
    "b79fbf4d-3ef9-4689-8143-76b194e85509"
  ],`,
			Expected: map[string]struct{}{
				"xhoaxiuqng.onmicrosoft.com": {},
			},
		},

		// Arbitrary test cases
		"spacing": {
			Input: `| Variable name     | Description                                                   | Example value                         |
| ----------------- | ------------------------------------------------------------- | ------------------------------------- |
| AFASBaseUri       | Base URI of the AFAS REST API endpoint for this environment   | https://12345.rest.afas.online/ProfitRestServices |
| AFASToke          | App token in XML format for this environment                  | \<token>\<version>1\</version>\<data>D5R324DD5F4TRD945E530ED3CDD70D94BBDEC4C732B43F285ECB12345678\</data>\</token>    |
| AADtenantID       | Id of the Azure tenant                                        | 12fc345b-0c67-4cde-8902-dabf2cad34b5  |
| AADAppId          | Id of the Azure app                                           | f12345c6-7890-1f23-b456-789eb0bb1c23  |
| AADAppSecret      | Secret of the Azure app                                       | G1X2HsBw-co3dTIB45RE6vY.mSU~6u.7.8    |`,
			Expected: map[string]struct{}{
				"12fc345b-0c67-4cde-8902-dabf2cad34b5": {},
			},
		},
		"newline": {
			Input: `        {\n   \"mode\": \"Manual\"\n  },\n  \"bootstrapProfile\": {\n   \"artifactSource\":
        \"Direct\"\n  }\n },\n \"identity\": {\n  \"type\": \"SystemAssigned\",\n
        \ \"principalId\":\"00000000-0000-0000-0000-000000000001\",\n  \"tenantId\":
        \"d0a69dfd-9b9e-4833-9c33-c7903dd2e012\"\n },\n \"sku\": {\n  \"name\": \"Base\",\n
        \ \"tier\": \"Free\"\n }\n}"
    headers:`,
			Expected: map[string]struct{}{
				"d0a69dfd-9b9e-4833-9c33-c7903dd2e012": {},
			},
		},

		// False positives
		"tid shouldn't match clientId": {
			Input:    `"userId": "jdoe@businesscorp.ca", "isUserIdDisplayable": true, "isMRRT": true, "_clientId": "d3590ed6-52b3-4102-aeff-aad2292ab01c", }`,
			Expected: nil,
		},
		"tid shouldn't match subscription_id": {
			Input: `location = "eastus"
subscription_id = "47ab1364-000d-4a53-838d-1537b1e3b49f"`,
			Expected: nil,
		},
	}

	runPatTest(t, cases, FindTenantIdMatches)
}

func Test_FindClientIdMatches(t *testing.T) {
	cases := map[string]testCase{
		"app": {
			Input: `var app = "4ba50db1-3f3f-4521-8a9a-1be0864d922a"`,
			Expected: map[string]struct{}{
				"4ba50db1-3f3f-4521-8a9a-1be0864d922a": {},
			},
		},
		"appid": {
			Input: `The output includes credentials that you must protect. Be sure that you do not include these credentials in your code or check the credentials into your source control. For more information, see https://aka.ms/azadsp-cli
{
  "appId": "4ba50db1-3f3f-4521-8a9a-1be0864d922a",
  "displayName": "azure-cli-2022-12-02-15-40-24",`,
			Expected: map[string]struct{}{
				"4ba50db1-3f3f-4521-8a9a-1be0864d922a": {},
			},
		},
		"app_id": {
			Input: `msal:
	app_id: 'b9cbc91c-c890-4824-a487-91611bb0615a'`,
			Expected: map[string]struct{}{
				"b9cbc91c-c890-4824-a487-91611bb0615a": {},
			},
		},
		"application": {
			Input: `const application = \x60902aeb6d-29c7-4f6e-849d-4b933117e320\x60`,
			Expected: map[string]struct{}{
				"902aeb6d-29c7-4f6e-849d-4b933117e320": {},
			},
		},
		"applicationid": {
			Input: `# Login using Service Principal
$ApplicationId = "1e002bca-c6e2-446e-a29e-a221909fe8aa"`,
			Expected: map[string]struct{}{
				"1e002bca-c6e2-446e-a29e-a221909fe8aa": {},
			},
		},
		"application id": {
			Input: `The application id is "029e3b51-60dd-47aa-81ad-3c15b389db86", you need to`,
			Expected: map[string]struct{}{
				"029e3b51-60dd-47aa-81ad-3c15b389db86": {},
			},
		},
		"application_id": {
			Input: `        credential:
          application_id: |
			bafe0126-03eb-4917-b3ff-4601c4e8f12f`,
			Expected: map[string]struct{}{
				"bafe0126-03eb-4917-b3ff-4601c4e8f12f": {},
			},
		},
		"application-id": {
			Input: `vcap.services.msal.application-id: 0704100e-7e76-4e62-bfb6-70bfd33906e2`,
			Expected: map[string]struct{}{
				"0704100e-7e76-4e62-bfb6-70bfd33906e2": {},
			},
		},
		"client": {
			Input: `String client = "902aeb6d-29c7-4f6e-849d-4b933117e320";`,
			Expected: map[string]struct{}{
				"902aeb6d-29c7-4f6e-849d-4b933117e320": {},
			},
		},
		"clientid": {
			Input: `export const msalConfig = {
  auth: {
    clientId: '82c54108-535c-40b2-87dc-2db599df3810',`,
			Expected: map[string]struct{}{
				"82c54108-535c-40b2-87dc-2db599df3810": {},
			},
		},
		"client id": {
			Input: `The client ID is: a54e584d-6fc4-464c-8479-dc67b5d87ab9`,
			Expected: map[string]struct{}{
				"a54e584d-6fc4-464c-8479-dc67b5d87ab9": {},
			},
		},
		"client_id": {
			Input: `location = "eastus"
client_id = "89d5bd08-0d51-42cd-8eab-382c3ce11199"
subscription_id = "47ab1364-000d-4a53-838d-1537b1e3b49f"
`,
			Expected: map[string]struct{}{
				"89d5bd08-0d51-42cd-8eab-382c3ce11199": {},
			},
		},
		"client-id": {
			Input: `@TestPropertySource(properties = {
        "cas.authn.azure-active-directory.client-id=532c556b-1260-483f-9695-68d087fcd965",
        "cas.authn.azure-active-directory.client-secret`,
			Expected: map[string]struct{}{
				"532c556b-1260-483f-9695-68d087fcd965": {},
			},
		},
		"username": {
			Input: `az login --service-principal --username "21e144ac-532d-49ad-ba15-1c40694ce8b1" --password`,
			Expected: map[string]struct{}{
				"21e144ac-532d-49ad-ba15-1c40694ce8b1": {},
			},
		},
		"-u": {
			Input: `az login --service-principal -u "21e144ac-532d-49ad-ba15-1c40694ce8b1" -p`,
			Expected: map[string]struct{}{
				"21e144ac-532d-49ad-ba15-1c40694ce8b1": {},
			},
		},

		// Arbitrary test cases
		"spacing": {
			Input: `| Variable name     | Description                                                   | Example value                         |
| ----------------- | ------------------------------------------------------------- | ------------------------------------- |
| AFASBaseUri       | Base URI of the AFAS REST API endpoint for this environment   | https://12345.rest.afas.online/ProfitRestServices |
| AFASToke          | App token in XML format for this environment                  | \<token>\<version>1\</version>\<data>D5R324DD5F4TRD945E530ED3CDD70D94BBDEC4C732B43F285ECB12345678\</data>\</token>    |
| AADtenantID       | Id of the Azure tenant                                        | 12fc345b-0c67-4cde-8902-dabf2cad34b5  |
| AADAppId          | Id of the Azure app                                           | f12345c6-7890-1f23-b456-789eb0bb1c23  |
| AADAppSecret      | Secret of the Azure app                                       | G1X2HsBw-co3dTIB45RE6vY.mSU~6u.7.8    |`,
			Expected: map[string]struct{}{
				"f12345c6-7890-1f23-b456-789eb0bb1c23": {},
			},
		},
	}

	runPatTest(t, cases, FindClientIdMatches)
}
