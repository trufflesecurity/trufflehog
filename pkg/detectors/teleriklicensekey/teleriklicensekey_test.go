package teleriklicensekey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestTeleriklicensekey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "Valid JWT - Telerik License Key",
			input: `
				[INFO] Checking for Telerik License key
				[DEBUG] Using eyJhbGciOiJSUzI1NiIsInR5cCI6IlRlbGVyaWsgTGljZW5zZSBLZXkifQ.eyJ0eXBlIjoidGVsZXJpay1saWNlbnNlIiwibGljZW5zZUlkIjoiMTFjZjM1NTYtYTYxMS00MmVjLTkxZGYtMTZmMDdmMzAwZmJjIiwidXNlcklkIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiaWF0IjoxNzU5MTU0OTMxLCJsaWNlbnNlcyI6WyJleUpoYkdjaU9pSlNVekkxTmlJc0luUjVjQ0k2SWxSbGJHVnlhV3NnVEdsalpXNXpaU0JGZG1sa1pXNWpaU0o5LmV5SmpiMlJsSWpvaVZVbEJVMUJEVDFKRklpd2lkSGx3WlNJNkluTjFZbk5qY21sd2RHbHZiaUlzSW1WNGNHbHlZWFJwYjI0aU9qRTNOakUzTkRZNU16QXNJblZ6WlhKSlpDSTZJbUZoWVdGaFlXRmhMV0ppWW1JdFkyTmpZeTFrWkdSa0xXVmxaV1ZsWldWbFpXVmxaU0lzSW14cFkyVnVjMlZKWkNJNklqRXhZMll6TlRVMkxXRTJNVEV0TkRKbFl5MDVNV1JtTFRFMlpqQTNaak13TUdaaVl5SjkuMWtfTmhXSk9Na0s1amZ3WGh4OVZYdHVFbl9URjJsemJxbGFyWk5ZMU03eXo3X2c3blFEVlE1TzgzSmJaZ0hjRDdZQjREdDQzQndPNjVlYm03dWdaRUR2U3l1M2NnSkJtWndncUpHeXNNN3ZhYkNoVUxLX0Jqb01DVG1NY25FRzdKQ0h0N0R6U3JPb1VmckNESUhyZ1VXTWFPcWtGeFVYeWFKUUtLcTFhZDdNTVAtV05pYTdEbGVLVTRkQ2pKcU1EX21pd1pkTEVZRVphZXNBdFZsYXp5MHM1VU05YzgyM3BDOFZKU3NkTWhVcXMzU3M2aXFqWFB2RFRXejZ3aUZJdm9IVUxJLXYwRFBDN0kwUjQ3czlWQ3ZiZGl0QW9JWUNWRHJBa0dneFNwSHpmc0Zoa0J2NnZJcFVvLTQydXQyNWxKMFJEQXF4bFpWVHN4d3JMWTY2S2N3IiwiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklsUmxiR1Z5YVdzZ1RHbGpaVzV6WlNCRmRtbGtaVzVqWlNKOS5leUowZVhCbElqb2lkWE5oWjJVaUxDSjFjMlZ5U1dRaU9pSmhZV0ZoWVdGaFlTMWlZbUppTFdOalkyTXRaR1JrWkMxbFpXVmxaV1ZsWldWbFpXVWlMQ0pzYVdObGJuTmxTV1FpT2lJeE1XTm1NelUxTmkxaE5qRXhMVFF5WldNdE9URmtaaTB4Tm1Zd04yWXpNREJtWW1NaUxDSnBjMGx1ZEdWeWJtRnNWWE5oWjJVaU9uUnlkV1Y5LkxtMVY0eHFJWUlIalRHbU94ZUkyd2x2dDFrVEMyZ01McE5UQ1pvYTZIbTdxdXJwZ0M3c1BVMFgxODd3eURYNmEwX0tvNnFOUGJTWlotNjJFdGNHNEwtLUE5MTZscEdtckRIS0Y4LXotRWJjMGVDSG9NM2U4R2ItVjF3c0pucGQ1LUhFYU0yYjZhR2JJTC1HTHllLVVraUVubEZVN2ZuNFktcEFSUVNBTVpKWTRqdnlMYS11OTloRzRKOGxHUGw4NTVUMEt3ci16dkRRUEZzQnB2eVhtMFV6Xy10THRSeHB3OTU0THl4WXNhR1l2RkVEZE1NQU5hWHN0UnFFNmRlNW9EWEJ2aEdIbXluaG9UUXREMHdTdlhKSXVhcms2bk1TWm52Q0JlUEllY2Z4dVNLMmMwNFdLa1FLMkNHMGxFOEE4S3hjSDJHUE9RS0IyU2JEOGN6ci1EQSJdLCJwcm9kdWN0cyI6W10sImF1ZCI6InUqKioubioqKkB0KioqKioqLnRlc3QiLCJsaWNlbnNlSG9sZGVyIjoidSoqKi5uKioqQHQqKioqKioudGVzdCIsImludGVncml0eSI6ImJqSHgvbUZSREloK1hsdWpJbUViM01ic2hKMWlsRzRSWDJEYlM1ZFJnaW89In0.ducvbQWc9JODoG9DFVMerhvuM2EsmsZRG-A8zhNzznJbIgxMAPeev0hcBIEYcSvPgmmAmjRBR1R_luBnl5sOMmP4h4BV0Mc5PY4prrOVEEDyabaKaiMtIUTJApG4gKOkOTZPiuP6DPJVMfy31YcLv0ldKfMJ004IAH1_cOjLVPDyEXlEb6RZv02xtho0Wgo5z6NtylVXO3JDv5F1v4vGibdPf3EY3blpzIVqEvm8NtWBHv44CbDUi8-nYzBf4ZDIg3kvJdOphW9KqHq6Kg7fT8jw5bTV-Lln438y-LMJWMS-agKkEFEJufi7nJjBnCSMasqKgbUQMyG8mFG8j79pOw
				[INFO] Result: Valid JWT containing a Telerik License Key.
			`,
			want: []string{"eyJhbGciOiJSUzI1NiIsInR5cCI6IlRlbGVyaWsgTGljZW5zZSBLZXkifQ.eyJ0eXBlIjoidGVsZXJpay1saWNlbnNlIiwibGljZW5zZUlkIjoiMTFjZjM1NTYtYTYxMS00MmVjLTkxZGYtMTZmMDdmMzAwZmJjIiwidXNlcklkIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiaWF0IjoxNzU5MTU0OTMxLCJsaWNlbnNlcyI6WyJleUpoYkdjaU9pSlNVekkxTmlJc0luUjVjQ0k2SWxSbGJHVnlhV3NnVEdsalpXNXpaU0JGZG1sa1pXNWpaU0o5LmV5SmpiMlJsSWpvaVZVbEJVMUJEVDFKRklpd2lkSGx3WlNJNkluTjFZbk5qY21sd2RHbHZiaUlzSW1WNGNHbHlZWFJwYjI0aU9qRTNOakUzTkRZNU16QXNJblZ6WlhKSlpDSTZJbUZoWVdGaFlXRmhMV0ppWW1JdFkyTmpZeTFrWkdSa0xXVmxaV1ZsWldWbFpXVmxaU0lzSW14cFkyVnVjMlZKWkNJNklqRXhZMll6TlRVMkxXRTJNVEV0TkRKbFl5MDVNV1JtTFRFMlpqQTNaak13TUdaaVl5SjkuMWtfTmhXSk9Na0s1amZ3WGh4OVZYdHVFbl9URjJsemJxbGFyWk5ZMU03eXo3X2c3blFEVlE1TzgzSmJaZ0hjRDdZQjREdDQzQndPNjVlYm03dWdaRUR2U3l1M2NnSkJtWndncUpHeXNNN3ZhYkNoVUxLX0Jqb01DVG1NY25FRzdKQ0h0N0R6U3JPb1VmckNESUhyZ1VXTWFPcWtGeFVYeWFKUUtLcTFhZDdNTVAtV05pYTdEbGVLVTRkQ2pKcU1EX21pd1pkTEVZRVphZXNBdFZsYXp5MHM1VU05YzgyM3BDOFZKU3NkTWhVcXMzU3M2aXFqWFB2RFRXejZ3aUZJdm9IVUxJLXYwRFBDN0kwUjQ3czlWQ3ZiZGl0QW9JWUNWRHJBa0dneFNwSHpmc0Zoa0J2NnZJcFVvLTQydXQyNWxKMFJEQXF4bFpWVHN4d3JMWTY2S2N3IiwiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklsUmxiR1Z5YVdzZ1RHbGpaVzV6WlNCRmRtbGtaVzVqWlNKOS5leUowZVhCbElqb2lkWE5oWjJVaUxDSjFjMlZ5U1dRaU9pSmhZV0ZoWVdGaFlTMWlZbUppTFdOalkyTXRaR1JrWkMxbFpXVmxaV1ZsWldWbFpXVWlMQ0pzYVdObGJuTmxTV1FpT2lJeE1XTm1NelUxTmkxaE5qRXhMVFF5WldNdE9URmtaaTB4Tm1Zd04yWXpNREJtWW1NaUxDSnBjMGx1ZEdWeWJtRnNWWE5oWjJVaU9uUnlkV1Y5LkxtMVY0eHFJWUlIalRHbU94ZUkyd2x2dDFrVEMyZ01McE5UQ1pvYTZIbTdxdXJwZ0M3c1BVMFgxODd3eURYNmEwX0tvNnFOUGJTWlotNjJFdGNHNEwtLUE5MTZscEdtckRIS0Y4LXotRWJjMGVDSG9NM2U4R2ItVjF3c0pucGQ1LUhFYU0yYjZhR2JJTC1HTHllLVVraUVubEZVN2ZuNFktcEFSUVNBTVpKWTRqdnlMYS11OTloRzRKOGxHUGw4NTVUMEt3ci16dkRRUEZzQnB2eVhtMFV6Xy10THRSeHB3OTU0THl4WXNhR1l2RkVEZE1NQU5hWHN0UnFFNmRlNW9EWEJ2aEdIbXluaG9UUXREMHdTdlhKSXVhcms2bk1TWm52Q0JlUEllY2Z4dVNLMmMwNFdLa1FLMkNHMGxFOEE4S3hjSDJHUE9RS0IyU2JEOGN6ci1EQSJdLCJwcm9kdWN0cyI6W10sImF1ZCI6InUqKioubioqKkB0KioqKioqLnRlc3QiLCJsaWNlbnNlSG9sZGVyIjoidSoqKi5uKioqQHQqKioqKioudGVzdCIsImludGVncml0eSI6ImJqSHgvbUZSREloK1hsdWpJbUViM01ic2hKMWlsRzRSWDJEYlM1ZFJnaW89In0.ducvbQWc9JODoG9DFVMerhvuM2EsmsZRG-A8zhNzznJbIgxMAPeev0hcBIEYcSvPgmmAmjRBR1R_luBnl5sOMmP4h4BV0Mc5PY4prrOVEEDyabaKaiMtIUTJApG4gKOkOTZPiuP6DPJVMfy31YcLv0ldKfMJ004IAH1_cOjLVPDyEXlEb6RZv02xtho0Wgo5z6NtylVXO3JDv5F1v4vGibdPf3EY3blpzIVqEvm8NtWBHv44CbDUi8-nYzBf4ZDIg3kvJdOphW9KqHq6Kg7fT8jw5bTV-Lln438y-LMJWMS-agKkEFEJufi7nJjBnCSMasqKgbUQMyG8mFG8j79pOw"},
		},
		{
			name: "Valid JWT - Not a Telerik License Key",
			input: `
				[INFO] Checking for Telerik License key
				[DEBUG] Using eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30
				[ERROR] Response received: Valid JWT, but is not a Telerik License Key.
			`,
			want: []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"},
		},
		{
			name: "Malformed JWT - no JWT pattern detected",
			input: `
				[INFO] Checking for Telerik License key
				[DEBUG] Using MjM0NTY3ODkwIiwibmFtZSI6Ik
				[ERROR] Response received: Not a valid base64url JWT.
			`,
			want: []string{},
		},
		{
			name: "No JWT present",
			input: `
				[INFO] Checking for Telerik License key
				[DEBUG] Using some other text that doesn't contain JWT.
				[ERROR] Response received: No JWT present.
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))

			// If we expect no results, and no detectors were matched, that's correct
			if len(test.want) == 0 {
				if len(matchedDetectors) > 0 {
					t.Errorf("test %q failed: expected no keywords to be found but found %v", test.name, d.Keywords())
				}
				return
			}

			// If we expect results but no detectors were matched, that's an error
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
