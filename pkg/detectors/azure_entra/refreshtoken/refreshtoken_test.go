package refreshtoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestRefreshToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// Valid - 0.
		{
			name:  "valid - token only",
			input: `"refresh_token": "0.AXEAFN5Pl6TDG0ibA8_OGCw6B-kFbFJoXnhBqmJD9wukrpZxAMc.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P9g0VCdz8smoWqJBpit_3P_ntszmbCH2-dGwpsamwQMbLl7QBa7tlfXH_NtpD1vNTGkacraUMyTM5lfg1AR1DLAxs-pNSpg8NfrHbNSRAIacCpOyqtU05Dg9l5LC7ZYwxT35dQWEK0EExLER-wxjW9DrDZNQV4J3Ktv1Z4ANT2N2rqAjPYqHTDPCCcOi980ptizeImgVYiVr37Ff0Hnr_lAi4Em0wGB7KDdu319sV9Sebe91FIRDs7GVvvv7GFvKjTeXJwHCpbhdqX4X2TRMryNrTNZ8QY7_Wa25MQm7v0qfFqDW_pRMxxohGhClSedZFnkzrreIhZ8ULJ9NCf8YENRHDP3LuOJP5gex-H0MUNsJQLxlDq3bH-i7Fz_cTEB3UN_bvgE9aNe-5gal-ykO_gSx-Kk5D-vZWpLDrFUdRSGYHmKr1zgEZvQjsFUj8pGWgUwssqN9SOPxTYIEzQaxPAul5AFKcxGYt2l4Kvhh58txUdayFAglWrkx1lrxnpIcjoRmHOo45AKlgH30bVOjjltwvD4L9SGMAHhni3F6mCB6aNLGpYCHjrbdsiWolHKV0leJmBYl2Ye4eosQf9YYdgPAbCQKqOJ6gfrxJJTcfrISqDVw1c6C9qPPdHbvdol_KfdJntyfuPpHovx7AfARBcjb6nMgYRBI0wFWsGuTNDcylicMFRcZx6v283wBv4U_0PrG1_Yd5ktfgaTVXF733C-ma_-s49tAvtDrJz2bmNFpotLyyQmwOiApLjeWFkH8EjBsBtpjhzzCIrOHuHR1I1gHChDMMDxfFT2k8dqxkvBpMLZ3zFWyJNl3LYbjgy9BkTIngvpQMSgRMl_VZ2eN_fZWk5wVOHjiUJJ9n4Y8IKQRM731vK_XEaK_BdtNLfC1Gw8hfLrIZpC6152zj6RhPn03gOK7G4RL6S21IfWKrw4kl6rdaPLgmMxlaI"`,
			want:  []string{"0.AXEAFN5Pl6TDG0ibA8_OGCw6B-kFbFJoXnhBqmJD9wukrpZxAMc.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P9g0VCdz8smoWqJBpit_3P_ntszmbCH2-dGwpsamwQMbLl7QBa7tlfXH_NtpD1vNTGkacraUMyTM5lfg1AR1DLAxs-pNSpg8NfrHbNSRAIacCpOyqtU05Dg9l5LC7ZYwxT35dQWEK0EExLER-wxjW9DrDZNQV4J3Ktv1Z4ANT2N2rqAjPYqHTDPCCcOi980ptizeImgVYiVr37Ff0Hnr_lAi4Em0wGB7KDdu319sV9Sebe91FIRDs7GVvvv7GFvKjTeXJwHCpbhdqX4X2TRMryNrTNZ8QY7_Wa25MQm7v0qfFqDW_pRMxxohGhClSedZFnkzrreIhZ8ULJ9NCf8YENRHDP3LuOJP5gex-H0MUNsJQLxlDq3bH-i7Fz_cTEB3UN_bvgE9aNe-5gal-ykO_gSx-Kk5D-vZWpLDrFUdRSGYHmKr1zgEZvQjsFUj8pGWgUwssqN9SOPxTYIEzQaxPAul5AFKcxGYt2l4Kvhh58txUdayFAglWrkx1lrxnpIcjoRmHOo45AKlgH30bVOjjltwvD4L9SGMAHhni3F6mCB6aNLGpYCHjrbdsiWolHKV0leJmBYl2Ye4eosQf9YYdgPAbCQKqOJ6gfrxJJTcfrISqDVw1c6C9qPPdHbvdol_KfdJntyfuPpHovx7AfARBcjb6nMgYRBI0wFWsGuTNDcylicMFRcZx6v283wBv4U_0PrG1_Yd5ktfgaTVXF733C-ma_-s49tAvtDrJz2bmNFpotLyyQmwOiApLjeWFkH8EjBsBtpjhzzCIrOHuHR1I1gHChDMMDxfFT2k8dqxkvBpMLZ3zFWyJNl3LYbjgy9BkTIngvpQMSgRMl_VZ2eN_fZWk5wVOHjiUJJ9n4Y8IKQRM731vK_XEaK_BdtNLfC1Gw8hfLrIZpC6152zj6RhPn03gOK7G4RL6S21IfWKrw4kl6rdaPLgmMxlaI"},
		},
		{
			name: "valid - token+client+tenant",
			input: `
					{
						"tokenType": "Bearer",
						"expiresIn": 4742,
						"expiresOn": "2024-06-07 09:09:22.294640",
						"resource": "https://graph.windows.net",
						"accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
						"refreshToken": "0.AUUAMe_N-B6jSkuT5F9XHpElWlj2JcxuFFnRLm_3awiSnuJQsa1.AgABAwEAAADnfolhJpSnRYB1SVj-Hgd8Agrf-wUA9P9oElBtlKe8a-5_1t2eEmBef50SCv8exOOrgjUFMLtPQj_XH1rq3Onj2dCFQaHzhm7DfoOxj5LH4kR9jPIbPf2yRI0CgxFLEGMf0biO9LxmvVwb_NKTScIc_MK4eBsXG-En_e3vaIJS5t-ghSvPAKzl3pxiYVvBdP1i_nUHPl4dsCkk9SKCexWnhi4tg9xVVIi-MIkGDJxThmuKfAko1VHMgx-tsHRKgPoXlJi51uNO0KQQUxnDnjiWmLapCe3hVtjfoINBlb3CpiHkfW5G9dzF4cmFOQJQG9RdW-CU6t4VmlamK9gSbNYfyd7fWr7Ebv9Bo06eWEwEBpQmJONJERNScnqMs5Ztba9kUHchXqJd9wZMH-NtWejuR92IqMmPoaY4DP52Yodu2hWZPv0pFEFsthPJ3YpViOaJnCoSQ7ba-qzVr8TnvFlkI8EfFKNbl47_WncwKXDrPk2FlZwG4ywX7s0dXYvXDJ-rMQHsDcJDMABQXrxaU0Z7ozCk_ftVgBQocWZHAkzBtWZNw9dS4ltux0GeAYekUjzE7UYrPw41DLWOLrr7V-kx5sZ6h66iiTi-zdsJ28LnRIX4aZ6IC7jxIG0FK-roPldOEjy0XJ-V6QmyjkEYT3PK23vUTHIz3EQ8JqGNJMJO5mWwbedlIl2xq-0CczybkR2MJgr4UAQKUBFMYuUYGWrVygte9d48usQ6-MhAavmkyZb5Mo_PeMnnNef-cl6c8RUzMAOpeiumFEG-gTzyDgaoM1eFjtYKTz0mr-0lPfrEavE4LfGXh87oDb0lNrbbkMNhAXjz2rJW8ex1REfeBH4oit0WeMWH-sIvpT3H8jsYIawfPp7rBN9z_TMX9AUbqROEY2Nv1jSJsXCX0sjLRweYiQnl-hHFfLcWwFIFjMfs7eOKSiOBKB3ZqjQw_A8OVDxhAQJybiVgW8U41IAjXGX0DNilrmE0PhDAqs5jQIBSO66G05yJj1RY3b2z8cYMG1lKAZ10IIDfo8f3FU-_m-w6zNVVkNZko89bX8tA91EjXpoUvmnPZKT84Qx9KvtRM561ABVEYnE152821Xy0HeObVue6M5WlF0puvqk1HnkfAUDxMk6qO1Xy7o0myTIV1R2yxFPpQX_pwCRB1IutSqz0s6E1XyfbRyv8TKxjX3_tGgvUy8KrZFeYJ9pRFsKIN_AJ9_a2GMG6h1b9aCIaA7jGlOkYlC-4LnhqoKxs4RpJJIpWWN6wZstGmIACwJS4",
						"familyName": "Doe",
						"givenName": "John",
						"identityProvider": "live.com",
						"tenantId": "16515984-9303-47f6-a59f-917611c8cb2b",
						"userId": "john.doe@outlook.com",
						"isUserIdDisplayable": true,
						"isMRRT": true,
						"_clientId": "1b730954-1685-4b74-9bfd-dac224a7b894",
						"_authority": "https://login.microsoftonline.com/16515984-9303-47f6-a59f-917611c8cb2b"
					}`,
			want: []string{`{"refreshToken":"0.AUUAMe_N-B6jSkuT5F9XHpElWlj2JcxuFFnRLm_3awiSnuJQsa1.AgABAwEAAADnfolhJpSnRYB1SVj-Hgd8Agrf-wUA9P9oElBtlKe8a-5_1t2eEmBef50SCv8exOOrgjUFMLtPQj_XH1rq3Onj2dCFQaHzhm7DfoOxj5LH4kR9jPIbPf2yRI0CgxFLEGMf0biO9LxmvVwb_NKTScIc_MK4eBsXG-En_e3vaIJS5t-ghSvPAKzl3pxiYVvBdP1i_nUHPl4dsCkk9SKCexWnhi4tg9xVVIi-MIkGDJxThmuKfAko1VHMgx-tsHRKgPoXlJi51uNO0KQQUxnDnjiWmLapCe3hVtjfoINBlb3CpiHkfW5G9dzF4cmFOQJQG9RdW-CU6t4VmlamK9gSbNYfyd7fWr7Ebv9Bo06eWEwEBpQmJONJERNScnqMs5Ztba9kUHchXqJd9wZMH-NtWejuR92IqMmPoaY4DP52Yodu2hWZPv0pFEFsthPJ3YpViOaJnCoSQ7ba-qzVr8TnvFlkI8EfFKNbl47_WncwKXDrPk2FlZwG4ywX7s0dXYvXDJ-rMQHsDcJDMABQXrxaU0Z7ozCk_ftVgBQocWZHAkzBtWZNw9dS4ltux0GeAYekUjzE7UYrPw41DLWOLrr7V-kx5sZ6h66iiTi-zdsJ28LnRIX4aZ6IC7jxIG0FK-roPldOEjy0XJ-V6QmyjkEYT3PK23vUTHIz3EQ8JqGNJMJO5mWwbedlIl2xq-0CczybkR2MJgr4UAQKUBFMYuUYGWrVygte9d48usQ6-MhAavmkyZb5Mo_PeMnnNef-cl6c8RUzMAOpeiumFEG-gTzyDgaoM1eFjtYKTz0mr-0lPfrEavE4LfGXh87oDb0lNrbbkMNhAXjz2rJW8ex1REfeBH4oit0WeMWH-sIvpT3H8jsYIawfPp7rBN9z_TMX9AUbqROEY2Nv1jSJsXCX0sjLRweYiQnl-hHFfLcWwFIFjMfs7eOKSiOBKB3ZqjQw_A8OVDxhAQJybiVgW8U41IAjXGX0DNilrmE0PhDAqs5jQIBSO66G05yJj1RY3b2z8cYMG1lKAZ10IIDfo8f3FU-_m-w6zNVVkNZko89bX8tA91EjXpoUvmnPZKT84Qx9KvtRM561ABVEYnE152821Xy0HeObVue6M5WlF0puvqk1HnkfAUDxMk6qO1Xy7o0myTIV1R2yxFPpQX_pwCRB1IutSqz0s6E1XyfbRyv8TKxjX3_tGgvUy8KrZFeYJ9pRFsKIN_AJ9_a2GMG6h1b9aCIaA7jGlOkYlC-4LnhqoKxs4RpJJIpWWN6wZstGmIACwJS4","clientId":"1b730954-1685-4b74-9bfd-dac224a7b894","tenantId":"16515984-9303-47f6-a59f-917611c8cb2b"}`},
		},
		{
			name: "valid - 0. in README",
			input: `
				### Connection settings

				The connection settings are defined in the automation variables.
				1. Create the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)

				| Variable name     | Description                                                   | Example value                         |
				| ----------------- | ------------------------------------------------------------- | ------------------------------------- |
				| AFASBaseUri       | Base URI of the AFAS REST API endpoint for this environment   | https://12345.rest.afas.online/ProfitRestServices |
				| AFASToke          | App token in XML format for this environment                  | \<token>\<version>1\</version>\<data>D5R324DD5F4TRD945E530ED3CDD70D94BBDEC4C732B43F285ECB12345678\</data>\</token>    |
				| AADtenantID       | Id of the Azure tenant                                        | 12fc345b-0c67-4cde-8902-dabf2cad34b5  |
				| AADAppId          | Id of the Azure app                                           | f12345c6-7890-1f23-b456-789eb0bb1c23  |
				| AADRefreshToken   | Refresh token of the Azure app                                | 0.ABCDEFGHIJKLMNOPQRS_PK0mtsE5afl5BYdPsASFbrS7jIZ0AAc.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P-XOTtPMo2xp9vfbHGvVkHaBZh4D3YmTkx_WagBOk358QjDwHUsiuVvyKvP6FTbQQt8kCidfMC9cmIYesHG4Ft2B1HwJNX28OpiFPuFti1D4Is30GgQ685i_ovS4iXDCUgtm2zpI6ZQJVqoOidXZQW_lSupdcclMK_JCIb7LBuJBDXfy0-f75C734_nxL0nggS9mn-e_KuJpHvypvU8OS9MPDBArhUopZum2y-2oNE65Wr-xpKm_Zeyr3iUGSZg98nbaryHw-lbeyFC8LcNqqMB_T7BcgvJicHSnj6DtjjpMyjKMwsCAnxz2bUYoLLjGFHk8EhDUCuV9lzUW1BTko5_I31TQdX0XY94vHTU34N93t3QPrQFMf8UhDjfQKiCDj3r2b7YR9ndS8MNp9MIa1CbL8vI4EM8GO4wtVI30Dhca4HaMtpph6uJp3echt-q7AVNQ_7ZHgx_YFZNqDmJyYq3nrae7LYRo0kvM382ss7JpCylodwya89mC_SlnrFhLM_zbt1TQkOtZqiVHbdQk3z-MX1iZso5Mk17Yks1ao0mS0RJfWVWSlOq_Sp-2yaiCsP-lV1PVdvvY_AkuOulP1kPG_VfC0DN3pGjSQJ8J9Ot5hfyElWyPst9Nc-ODErLhEqIl-3IR6wPKFN2ffjt8-dtCVMlVdBd1QANQOFBiIGA-_BZdGLvzROrWCOE9dDtyBQ_LnxdnnOVdjUqJ-xdql1p13Xjy6ZTtcZtTDmFN5hSMffYuUtuwEOy_Xb91Y2tvwOxcSe9dj7ElOLZDo2C7fGsMgaIJ1gK8xt9OWsS1o1sQZKQADTZq5TTxJp7PY3tJsUnOlD4q8ZEyVBQAvRKinpajBRcbq2lTCVt0JgXAryWztqYTpAxiqaBr51vuR4pbVRtKv-h_10tYD-TUV1WeX2fY3GuZA4B5g |

				## contents`,
			want: []string{`{"refreshToken":"0.ABCDEFGHIJKLMNOPQRS_PK0mtsE5afl5BYdPsASFbrS7jIZ0AAc.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P-XOTtPMo2xp9vfbHGvVkHaBZh4D3YmTkx_WagBOk358QjDwHUsiuVvyKvP6FTbQQt8kCidfMC9cmIYesHG4Ft2B1HwJNX28OpiFPuFti1D4Is30GgQ685i_ovS4iXDCUgtm2zpI6ZQJVqoOidXZQW_lSupdcclMK_JCIb7LBuJBDXfy0-f75C734_nxL0nggS9mn-e_KuJpHvypvU8OS9MPDBArhUopZum2y-2oNE65Wr-xpKm_Zeyr3iUGSZg98nbaryHw-lbeyFC8LcNqqMB_T7BcgvJicHSnj6DtjjpMyjKMwsCAnxz2bUYoLLjGFHk8EhDUCuV9lzUW1BTko5_I31TQdX0XY94vHTU34N93t3QPrQFMf8UhDjfQKiCDj3r2b7YR9ndS8MNp9MIa1CbL8vI4EM8GO4wtVI30Dhca4HaMtpph6uJp3echt-q7AVNQ_7ZHgx_YFZNqDmJyYq3nrae7LYRo0kvM382ss7JpCylodwya89mC_SlnrFhLM_zbt1TQkOtZqiVHbdQk3z-MX1iZso5Mk17Yks1ao0mS0RJfWVWSlOq_Sp-2yaiCsP-lV1PVdvvY_AkuOulP1kPG_VfC0DN3pGjSQJ8J9Ot5hfyElWyPst9Nc-ODErLhEqIl-3IR6wPKFN2ffjt8-dtCVMlVdBd1QANQOFBiIGA-_BZdGLvzROrWCOE9dDtyBQ_LnxdnnOVdjUqJ-xdql1p13Xjy6ZTtcZtTDmFN5hSMffYuUtuwEOy_Xb91Y2tvwOxcSe9dj7ElOLZDo2C7fGsMgaIJ1gK8xt9OWsS1o1sQZKQADTZq5TTxJp7PY3tJsUnOlD4q8ZEyVBQAvRKinpajBRcbq2lTCVt0JgXAryWztqYTpAxiqaBr51vuR4pbVRtKv-h_10tYD-TUV1WeX2fY3GuZA4B5g","clientId":"f12345c6-7890-1f23-b456-789eb0bb1c23","tenantId":"12fc345b-0c67-4cde-8902-dabf2cad34b5"}`},
		},

		// Valid 1.
		{
			name: "valid - 1. token only",
			input: ` "refresh_token": "1.AVEAPn9m_nUaQ0iPPuqFsWAkYjIyPGgTIDFBgPvLEoUSLQVRAG5RAA.AgABAwEAAADW6jl31mB3T7ugrWTT8pFeAwDj_wUA9P8ZsxEzkXInsWHkCylMQMSSKto-NoegPmNj0uIemgAvxjnsDVGpC7sDRl4oEd51nQLQYowQYQ8aEcHh3nRrACc37UPYN-bwDte-tiwOEKuuGTOUrZft6YCqYiBoj7p3GZvKkIkUOGZvx7nydI1WoH9c7Z62NstZJ7ju_V38t5He6cKXEzNtlnrHpctxJX1uxxizdvwIR-_2VyMQjSSJS5lOS0Hi4Z_Nlthos5G-Gb-h9Y96fkkVm0D5E4xQh9avS7eCAPE2-N_guF3tmm7B4aqJg1lGnwv3WDWim14QhkF6Aji7juJUNmAExFyBaM7WnV_u3JnT-UNCz1p0O3AHa9d-dyDTUxQ8m_riB1HPoZZo6wPxg6txs6-fUE4LDR6tB5b43zwUl9XufcL4gKwnheLr8LvpJGjJn2tZUQzoU-ow4AZtJIxblfgYU_Zq0WOPJXltgAEw2JVoGsRy2jX8mXFZq1iCK5uEKBPXgrEfV-simUqI8GRZgXA1EnxG950MuaVfP3ZpsTYPGsvQgSzsUBKSy7cLd0p7UYtLub9UpX2PJxHrLQjACF-CSOMatVfSNzTErhSEmVWndpt87Yhova-XJUV48UxQ4ZZz26G6nOQ9qJ6db8ReAzBnok10e0eBuHR6K0OzcO54gjiQWPR4Tur7hD82KmYdOtShz234hDRGuS_b7mThfr_2ef9b2TQ9XYEV2QDUWiFYplfU0kOKA-wA7jOJGhXDkaJCIURxy53KuZPolXjTAy4",
					"expires_at": 1733138350.558087
					}`,
			want: []string{"1.AVEAPn9m_nUaQ0iPPuqFsWAkYjIyPGgTIDFBgPvLEoUSLQVRAG5RAA.AgABAwEAAADW6jl31mB3T7ugrWTT8pFeAwDj_wUA9P8ZsxEzkXInsWHkCylMQMSSKto-NoegPmNj0uIemgAvxjnsDVGpC7sDRl4oEd51nQLQYowQYQ8aEcHh3nRrACc37UPYN-bwDte-tiwOEKuuGTOUrZft6YCqYiBoj7p3GZvKkIkUOGZvx7nydI1WoH9c7Z62NstZJ7ju_V38t5He6cKXEzNtlnrHpctxJX1uxxizdvwIR-_2VyMQjSSJS5lOS0Hi4Z_Nlthos5G-Gb-h9Y96fkkVm0D5E4xQh9avS7eCAPE2-N_guF3tmm7B4aqJg1lGnwv3WDWim14QhkF6Aji7juJUNmAExFyBaM7WnV_u3JnT-UNCz1p0O3AHa9d-dyDTUxQ8m_riB1HPoZZo6wPxg6txs6-fUE4LDR6tB5b43zwUl9XufcL4gKwnheLr8LvpJGjJn2tZUQzoU-ow4AZtJIxblfgYU_Zq0WOPJXltgAEw2JVoGsRy2jX8mXFZq1iCK5uEKBPXgrEfV-simUqI8GRZgXA1EnxG950MuaVfP3ZpsTYPGsvQgSzsUBKSy7cLd0p7UYtLub9UpX2PJxHrLQjACF-CSOMatVfSNzTErhSEmVWndpt87Yhova-XJUV48UxQ4ZZz26G6nOQ9qJ6db8ReAzBnok10e0eBuHR6K0OzcO54gjiQWPR4Tur7hD82KmYdOtShz234hDRGuS_b7mThfr_2ef9b2TQ9XYEV2QDUWiFYplfU0kOKA-wA7jOJGhXDkaJCIURxy53KuZPolXjTAy4"},
		},
		{
			name: "valid - 1. tenant+client+token",
			input: `
				async function getAccessToken() {
				const tenantId = "31d1b7f4-4c4c-44cf-8d4e-b63e8512543e";
				const clientId = "16ed71fb-067e-47d9-b4bc-7656b14f1c5e";
				const clientSecret = ""; //para que funcione en sus ambientes tienen que poner el secreto, 
										//si no lo tienen me lo piden y se los comparto por whatsapp, 
										//lo tuvé que quitar porque no me dejaba hacer commit de los cambios en el repositorio
				const scope = "https://analysis.windows.net/powerbi/api/.default";
				let refresh_token = "1.AWEBqY9dsQppikubCN8WQsbFVyBfrV_ioNtAn7uoXAmQmkRiAUthAQ.AgABAwEAAADW6jl31mB3T7ugrWTT8pFeAwDs_yUA9P8OThUk9d3XIZbW4OGsJwHqqvjnVfcvEH4nejPU6R6-3onU34aSbVTEmxec0Nn3PaKfTBxucT-bu5XLSaTZSePKAAZw22RpqBb1w6ySb5GvvcCVpFU45mNfX5OH63y2Ryt-B7Beyp5yzlIgVgQA2S4OKhd_2qoVQoQXLApTwR78awwMFEQ7eVSbu5DO52dxisjB9ApHmpDCBip5y2MzyS7TizR31e-qBTnCMWt9RuHcKJySFFa-yPRBqYCgZLQWmEsKXBq-RIJToFsaGhVH2sXGXec0-Qsd9CvSPNFfGUDb_d2FLkZyKYKPra7Wmsvpw6qZJxO_TYprs1TbeWJYTTWT6WWI3xn10XtVml0a0P77ESqAWs-nbl6fS15mE24ZVU6rsuD7Q5AmtFfaddVN-JFP3fJ-6VsiY3KAefmdNULF_AVfMxAelBDSHtNllsMv4Qqs8N4h5bY4cabHibpu_OVA7WzfkNbxQ1dZpccZ9pi--xq5BCU3QAzereqYwmKretykB8twHw8Ryl5UVGocBNSJD65w2K3FJGZ6zbinfb_g1vV39iFxLdUz3JT1obce5ndeMBUeFmhN5XsczKAzTRK9c8aX6sdOd5pw5vUe-98qFRypPvCSF4hVA2ziwH38V9Dtc56UEVSMKISOacRMs8F_m9XtxP4X5KsWICIrK8_EXWfgmvEQnXm5PHV24ROsbnmmtUJWN1-vgzmNmSQ54_66W-fsCdnYAzDlwZeKr7wTZYO82nepNHX-wvTTEPV-QlrTPQFAlguP6nnxRc8MoxyiEvT4fOsDwD4yWFkLMMlKbyB6pQF_0CW_rQbyl0e6EKP2HbIDVKj628MDizjsdX693gplJevjF5g";
				`,
			want: []string{`{"refreshToken":"1.AWEBqY9dsQppikubCN8WQsbFVyBfrV_ioNtAn7uoXAmQmkRiAUthAQ.AgABAwEAAADW6jl31mB3T7ugrWTT8pFeAwDs_yUA9P8OThUk9d3XIZbW4OGsJwHqqvjnVfcvEH4nejPU6R6-3onU34aSbVTEmxec0Nn3PaKfTBxucT-bu5XLSaTZSePKAAZw22RpqBb1w6ySb5GvvcCVpFU45mNfX5OH63y2Ryt-B7Beyp5yzlIgVgQA2S4OKhd_2qoVQoQXLApTwR78awwMFEQ7eVSbu5DO52dxisjB9ApHmpDCBip5y2MzyS7TizR31e-qBTnCMWt9RuHcKJySFFa-yPRBqYCgZLQWmEsKXBq-RIJToFsaGhVH2sXGXec0-Qsd9CvSPNFfGUDb_d2FLkZyKYKPra7Wmsvpw6qZJxO_TYprs1TbeWJYTTWT6WWI3xn10XtVml0a0P77ESqAWs-nbl6fS15mE24ZVU6rsuD7Q5AmtFfaddVN-JFP3fJ-6VsiY3KAefmdNULF_AVfMxAelBDSHtNllsMv4Qqs8N4h5bY4cabHibpu_OVA7WzfkNbxQ1dZpccZ9pi--xq5BCU3QAzereqYwmKretykB8twHw8Ryl5UVGocBNSJD65w2K3FJGZ6zbinfb_g1vV39iFxLdUz3JT1obce5ndeMBUeFmhN5XsczKAzTRK9c8aX6sdOd5pw5vUe-98qFRypPvCSF4hVA2ziwH38V9Dtc56UEVSMKISOacRMs8F_m9XtxP4X5KsWICIrK8_EXWfgmvEQnXm5PHV24ROsbnmmtUJWN1-vgzmNmSQ54_66W-fsCdnYAzDlwZeKr7wTZYO82nepNHX-wvTTEPV-QlrTPQFAlguP6nnxRc8MoxyiEvT4fOsDwD4yWFkLMMlKbyB6pQF_0CW_rQbyl0e6EKP2HbIDVKj628MDizjsdX693gplJevjF5g","clientId":"16ed71fb-067e-47d9-b4bc-7656b14f1c5e","tenantId":"31d1b7f4-4c4c-44cf-8d4e-b63e8512543e"}`},
		},
		{
			name: "valid - 1. with more than 3 segments",
			input: `- request:
					body: client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&grant_type=refresh_token&client_info=1&claims=%7B%22access_token%22%3A+%7B%22xms_cc%22%3A+%7B%22values%22%3A+%5B%22CP1%22%5D%7D%7D%7D&refresh_token=1.AAEA-W8xnNOnEke-ljgE71hsE5V3sATbjRpGu-4G-eG_e0YBAFIaAA.1.AgABAwEAAAAuQLDzsjJ3TYwhxABdnzRyAwDs_wUA7_9ENX2x1IM0b4hPzM-Ba_-qsHQqGxLKdo8wXF8BKQjnNc3wrqvP54z75uPEWb9uNOqw_Y8oxEQHggfkdIiq1NjPeA-A9jR2AI28nwlPd8dyuglTrUhLEKCKH0UFCeOi0lSxr7pefIa97LSJsDFKYPg1bCd9iuyRI5zQVGFbfHfq7gI8TSbpaVRSzNlsgftBrzIH_Zk55WCWz9ln8B-K1mc8gFDKsnclyvyCQU6e4CE0_6dHq1FXD-BwwV0yC1S9yyh673EHgY47s950p3Yqc7a8fOKY7iuwNKCDML51CUAZusRWfRYx0d1FXMI-JUfoBHTaZwsQyFePTlLjxkk2iEk4v9PTlTIvBdzZ6A8BVNDvpK_lBHgEpN_HVEbWM9ZHvWbeIU2_Lwt0SqLJEnq5GkTowX3aJe36JXWE6NBp5NJWS5-0EfEtl5iIWxtNG6u2E7lGAEbvUEAGXYa0abLxNwRiKvMNCKw01v42xIw1HqonNMT-tgY08KI3Icbyv-hzEwUwY8LYcjOGQTejDRe7CM9IogLe5flpK6m5aYKF8k4qVMN2PqCGCpofcqqyS448k9ATYx1Dm4-MAVsWScb22M106yIRSIbdo7tKdr3vBdNf0_FT0I-r20iDnUw_6sQc_Q8tR9uRuZbtrwD6IBAyYzqTG2KacAG6Gac-J5p-fsnPdjy0RmurvE149oA4G0KcAatNPmreiGzArXJEx7z20QwCgrh4j11j3dLJQMMafaxPdjHjPkwrG8Vz7xHVvRlfcn6x1d2Xhyq2VB6BwdZVIukbvxSg9Ci34qlKunOtohUxvisRRryV-w6MV1BomJz3W0QM0cTm5KVWpH9_0tQrioelqwvstQ6bOHRA3r7CzTZw0lfGMoDlaPubUqiy5t6P_b40hpkt40drKKHN972GwSDeR19cYiUFIONkc5APsV17tq0XZZgB8zpL-WilYK2SBQzescd4W1yXpFuh-uZ7bLAnQaa6xZzFDkN9-v4chZ2UAAvBsIURr7Q_8N_w2nH_.AQABFAEAAAAuQLDzsjJ3TYwhxABdnzRyNxO45BG1O4-twAhtMj2ZAGVMkIFTMaFoxpzzBJ7zB99xWtRIkmYAput3pQWfY44PP3WY0mRvEqSuLWlLa79Nz8jJANXNNTbPvXt8F_BDxeZUwb7gNax-q2Fr12Gb5YnTVnq9EUU9QEcuThPgC7tFWFu3_iwKjR-IMMcnQj6C7eh-ZcPMIn5Pkb3FkLwD7aZblol-4Z18pXV7dBOO8i0i4VZ5ud7tkxL5UjDZdbM8NrogAA&scope=https%3A%2F%2Fmanagement.core.windows.net%2F%2F.default+offline_access+openid+profile
					headers:`,
			want: []string{`1.AAEA-W8xnNOnEke-ljgE71hsE5V3sATbjRpGu-4G-eG_e0YBAFIaAA.1.AgABAwEAAAAuQLDzsjJ3TYwhxABdnzRyAwDs_wUA7_9ENX2x1IM0b4hPzM-Ba_-qsHQqGxLKdo8wXF8BKQjnNc3wrqvP54z75uPEWb9uNOqw_Y8oxEQHggfkdIiq1NjPeA-A9jR2AI28nwlPd8dyuglTrUhLEKCKH0UFCeOi0lSxr7pefIa97LSJsDFKYPg1bCd9iuyRI5zQVGFbfHfq7gI8TSbpaVRSzNlsgftBrzIH_Zk55WCWz9ln8B-K1mc8gFDKsnclyvyCQU6e4CE0_6dHq1FXD-BwwV0yC1S9yyh673EHgY47s950p3Yqc7a8fOKY7iuwNKCDML51CUAZusRWfRYx0d1FXMI-JUfoBHTaZwsQyFePTlLjxkk2iEk4v9PTlTIvBdzZ6A8BVNDvpK_lBHgEpN_HVEbWM9ZHvWbeIU2_Lwt0SqLJEnq5GkTowX3aJe36JXWE6NBp5NJWS5-0EfEtl5iIWxtNG6u2E7lGAEbvUEAGXYa0abLxNwRiKvMNCKw01v42xIw1HqonNMT-tgY08KI3Icbyv-hzEwUwY8LYcjOGQTejDRe7CM9IogLe5flpK6m5aYKF8k4qVMN2PqCGCpofcqqyS448k9ATYx1Dm4-MAVsWScb22M106yIRSIbdo7tKdr3vBdNf0_FT0I-r20iDnUw_6sQc_Q8tR9uRuZbtrwD6IBAyYzqTG2KacAG6Gac-J5p-fsnPdjy0RmurvE149oA4G0KcAatNPmreiGzArXJEx7z20QwCgrh4j11j3dLJQMMafaxPdjHjPkwrG8Vz7xHVvRlfcn6x1d2Xhyq2VB6BwdZVIukbvxSg9Ci34qlKunOtohUxvisRRryV-w6MV1BomJz3W0QM0cTm5KVWpH9_0tQrioelqwvstQ6bOHRA3r7CzTZw0lfGMoDlaPubUqiy5t6P_b40hpkt40drKKHN972GwSDeR19cYiUFIONkc5APsV17tq0XZZgB8zpL-WilYK2SBQzescd4W1yXpFuh-uZ7bLAnQaa6xZzFDkN9-v4chZ2UAAvBsIURr7Q_8N_w2nH_.AQABFAEAAAAuQLDzsjJ3TYwhxABdnzRyNxO45BG1O4-twAhtMj2ZAGVMkIFTMaFoxpzzBJ7zB99xWtRIkmYAput3pQWfY44PP3WY0mRvEqSuLWlLa79Nz8jJANXNNTbPvXt8F_BDxeZUwb7gNax-q2Fr12Gb5YnTVnq9EUU9QEcuThPgC7tFWFu3_iwKjR-IMMcnQj6C7eh-ZcPMIn5Pkb3FkLwD7aZblol-4Z18pXV7dBOO8i0i4VZ5ud7tkxL5UjDZdbM8NrogAA`},
		},

		// Invalid
		{
			name:  "invalid - too short",
			input: `"refresh_token": "0.AXEAFN5Pl6TDG0ibA8_OGCw6B-kFbFJoXnhBqmJD9wukrpZxAMc.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P9g0VCdz8sm..."`,
		},
		{
			name:  "invalid - low entropy",
			input: `"refresh_token": "0.Axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.Agxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
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
