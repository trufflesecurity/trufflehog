//go:build detectors
// +build detectors

package teleriklicensekey

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestTeleriklicensekey_FromChunk(t *testing.T) {
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	// defer cancel()

	//testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	// if err != nil {
	// 	t.Fatalf("could not get test secrets from GCP: %s", err)
	// }

	// secret := testSecrets.MustGetField("SECRET_TYPE_ONE")
	// inactiveSecret := testSecrets.MustGetField("SECRET_TYPE_ONE_INACTIVE")

	secret := "eyJhbGciOiJSUzI1NiIsInR5cCI6IlRlbGVyaWsgTGljZW5zZSBLZXkifQ.eyJ0eXBlIjoidGVsZXJpay1saWNlbnNlIiwibGljZW5zZUlkIjoiMTFjZjM1NTYtYTYxMS00MmVjLTkxZGYtMTZmMDdmMzAwZmJjIiwidXNlcklkIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiaWF0IjoxNzU5MTU0OTMxLCJsaWNlbnNlcyI6WyJleUpoYkdjaU9pSlNVekkxTmlJc0luUjVjQ0k2SWxSbGJHVnlhV3NnVEdsalpXNXpaU0JGZG1sa1pXNWpaU0o5LmV5SmpiMlJsSWpvaVZVbEJVMUJEVDFKRklpd2lkSGx3WlNJNkluTjFZbk5qY21sd2RHbHZiaUlzSW1WNGNHbHlZWFJwYjI0aU9qRTNOakUzTkRZNU16QXNJblZ6WlhKSlpDSTZJbUZoWVdGaFlXRmhMV0ppWW1JdFkyTmpZeTFrWkdSa0xXVmxaV1ZsWldWbFpXVmxaU0lzSW14cFkyVnVjMlZKWkNJNklqRXhZMll6TlRVMkxXRTJNVEV0TkRKbFl5MDVNV1JtTFRFMlpqQTNaak13TUdaaVl5SjkuMWtfTmhXSk9Na0s1amZ3WGh4OVZYdHVFbl9URjJsemJxbGFyWk5ZMU03eXo3X2c3blFEVlE1TzgzSmJaZ0hjRDdZQjREdDQzQndPNjVlYm03dWdaRUR2U3l1M2NnSkJtWndncUpHeXNNN3ZhYkNoVUxLX0Jqb01DVG1NY25FRzdKQ0h0N0R6U3JPb1VmckNESUhyZ1VXTWFPcWtGeFVYeWFKUUtLcTFhZDdNTVAtV05pYTdEbGVLVTRkQ2pKcU1EX21pd1pkTEVZRVphZXNBdFZsYXp5MHM1VU05YzgyM3BDOFZKU3NkTWhVcXMzU3M2aXFqWFB2RFRXejZ3aUZJdm9IVUxJLXYwRFBDN0kwUjQ3czlWQ3ZiZGl0QW9JWUNWRHJBa0dneFNwSHpmc0Zoa0J2NnZJcFVvLTQydXQyNWxKMFJEQXF4bFpWVHN4d3JMWTY2S2N3IiwiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklsUmxiR1Z5YVdzZ1RHbGpaVzV6WlNCRmRtbGtaVzVqWlNKOS5leUowZVhCbElqb2lkWE5oWjJVaUxDSjFjMlZ5U1dRaU9pSmhZV0ZoWVdGaFlTMWlZbUppTFdOalkyTXRaR1JrWkMxbFpXVmxaV1ZsWldWbFpXVWlMQ0pzYVdObGJuTmxTV1FpT2lJeE1XTm1NelUxTmkxaE5qRXhMVFF5WldNdE9URmtaaTB4Tm1Zd04yWXpNREJtWW1NaUxDSnBjMGx1ZEdWeWJtRnNWWE5oWjJVaU9uUnlkV1Y5LkxtMVY0eHFJWUlIalRHbU94ZUkyd2x2dDFrVEMyZ01McE5UQ1pvYTZIbTdxdXJwZ0M3c1BVMFgxODd3eURYNmEwX0tvNnFOUGJTWlotNjJFdGNHNEwtLUE5MTZscEdtckRIS0Y4LXotRWJjMGVDSG9NM2U4R2ItVjF3c0pucGQ1LUhFYU0yYjZhR2JJTC1HTHllLVVraUVubEZVN2ZuNFktcEFSUVNBTVpKWTRqdnlMYS11OTloRzRKOGxHUGw4NTVUMEt3ci16dkRRUEZzQnB2eVhtMFV6Xy10THRSeHB3OTU0THl4WXNhR1l2RkVEZE1NQU5hWHN0UnFFNmRlNW9EWEJ2aEdIbXluaG9UUXREMHdTdlhKSXVhcms2bk1TWm52Q0JlUEllY2Z4dVNLMmMwNFdLa1FLMkNHMGxFOEE4S3hjSDJHUE9RS0IyU2JEOGN6ci1EQSJdLCJwcm9kdWN0cyI6W10sImF1ZCI6InUqKioubioqKkB0KioqKioqLnRlc3QiLCJsaWNlbnNlSG9sZGVyIjoidSoqKi5uKioqQHQqKioqKioudGVzdCIsImludGVncml0eSI6ImJqSHgvbUZSREloK1hsdWpJbUViM01ic2hKMWlsRzRSWDJEYlM1ZFJnaW89In0.ducvbQWc9JODoG9DFVMerhvuM2EsmsZRG-A8zhNzznJbIgxMAPeev0hcBIEYcSvPgmmAmjRBR1R_luBnl5sOMmP4h4BV0Mc5PY4prrOVEEDyabaKaiMtIUTJApG4gKOkOTZPiuP6DPJVMfy31YcLv0ldKfMJ004IAH1_cOjLVPDyEXlEb6RZv02xtho0Wgo5z6NtylVXO3JDv5F1v4vGibdPf3EY3blpzIVqEvm8NtWBHv44CbDUi8-nYzBf4ZDIg3kvJdOphW9KqHq6Kg7fT8jw5bTV-Lln438y-LMJWMS-agKkEFEJufi7nJjBnCSMasqKgbUQMyG8mFG8j79pOw"

	inactiveSecret := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"

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
				data:   []byte(fmt.Sprintf("You can find a teleriklicensekey secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TelerikLicenseKey,
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
				data:   []byte(fmt.Sprintf("You can find a teleriklicensekey secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TelerikLicenseKey,
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
			name: "found, verified (no HTTP client needed for JWT validation)",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a teleriklicensekey secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TelerikLicenseKey,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, verified (local JWT validation)",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a teleriklicensekey secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TelerikLicenseKey,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Teleriklicensekey.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError", "primarySecret")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Teleriklicensekey.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
