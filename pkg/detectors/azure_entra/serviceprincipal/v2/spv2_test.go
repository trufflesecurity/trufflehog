package v2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type testCase struct {
	Input    string
	Expected map[string]struct{}
}

func Test_FindClientSecretMatches(t *testing.T) {
	cases := map[string]testCase{
		"secret": {
			Input: `servicePrincipal:
  tenantId: "608e4ac4-2ca8-40dd-a046-4064540a1cde"
  clientId: "1474bfe8-663c-486e-9daf-f1f580302218"
  clientSecret: "R028Q~ZOKzgCYyhr1ZJNNKhP8gUcD3Dpy2jMqaXf"
agentImage: "karbar.azurecr.io/kar-agent"`,
			Expected: map[string]struct{}{
				"R028Q~ZOKzgCYyhr1ZJNNKhP8gUcD3Dpy2jMqaXf": {},
			},
		},
		"secret_start_with_dash": {
			Input: `azure:
      active-directory:
        enabled: true
        profile:
          tenant-id: 11111111-1111-1111-1111-111111111111
        credential:
          client-id: 00000000-0000-0000-0000-000000000000
          client-secret: -bs8Q~F9mPSWiDihY0NIpcQjAWoUoQ.c-seM-c0_`,
			Expected: map[string]struct{}{
				"-bs8Q~F9mPSWiDihY0NIpcQjAWoUoQ.c-seM-c0_": {},
			},
		},
		"secret_end_with_dash": {
			Input: `OPENID_CLIENT_ID=8595f61a-109a-497d-8c8f-566b733e95fe
OPENID_CLIENT_SECRET=aZ78Q~C~--E4dgsHZklBWtAw0mdajUHAaXXG5cq-
OPENID_GRANT_TYPE=client_credentials`,
			Expected: map[string]struct{}{
				"aZ78Q~C~--E4dgsHZklBWtAw0mdajUHAaXXG5cq-": {},
			},
		},
		"client_secret": {
			Input: `      "RequestBody": "client_id=4cb7565b-9ff0-49ed-b317-4dace4a70396\u0026grant_type=client_credentials\u0026client_info=1\u0026client_secret=-6s8Q~.Q9CKMOXHGs_BA3ig2wUzyDRyulhWEOc3u\u0026claims=%7B%22access_token%22%3A\u002B%7B%22xms_cc%22%3A\u002B%7B%22values%22%3A\u002B%5B%22CP1%22%5D%7D%7D%7D\u0026scope=https%3A%2F%2Fmanagement.azure.com%2F.default",`,
			Expected: map[string]struct{}{
				"-6s8Q~.Q9CKMOXHGs_BA3ig2wUzyDRyulhWEOc3u": {},
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			matches := findSecretMatches(test.Input)
			if len(matches) == 0 {
				if len(test.Expected) != 0 {
					t.Fatalf("no matches found, expected: %v", test.Expected)
					return
				} else {
					return
				}
			}

			if diff := cmp.Diff(test.Expected, matches); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", name, diff)
			}
		})
	}
}
