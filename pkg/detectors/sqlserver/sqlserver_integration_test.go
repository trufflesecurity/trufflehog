//go:build detectors && integration
// +build detectors,integration

package sqlserver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/microsoft/go-mssqldb/msdsn"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mssql"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestSQLServerIntegration_FromChunk(t *testing.T) {
	ctx := context.Background()

	password := gofakeit.Password(true, true, true, false, false, 10)

	container, err := mssql.RunContainer(
		ctx,
		testcontainers.WithImage("mcr.microsoft.com/azure-sql-edge"),
		mssql.WithAcceptEULA(),
		mssql.WithPassword(password))
	if err != nil {
		t.Fatalf("could not start container: %v", err)
	}

	defer container.Terminate(ctx)

	port, err := container.MappedPort(ctx, "1433")
	if err != nil {
		t.Fatalf("could get mapped port: %v", err)
	}

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
				ctx: context.Background(),
				data: []byte(fmt.Sprintf("Server=localhost;Port=%s;Initial Catalog=master;User ID=sa;Password=%s;Persist Security Info=true;MultipleActiveResultSets=true;",
					port.Port(),
					password)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Raw:          []byte(password),
					RawV2: []byte(urlEncode(fmt.Sprintf("sqlserver://sa:%s@localhost:%s?database=master&dial+timeout=15&disableretry=false",
						password,
						port.Port()))),
					Redacted: fmt.Sprintf("sqlserver://sa:********@localhost:%s?database=master&dial+timeout=15&disableretry=false",
						port.Port()),
					Verified: true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("Server=localhost;Port=%s;User ID=sa;Password=123", port.Port())),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Raw:          []byte("123"),
					RawV2: []byte(fmt.Sprintf("sqlserver://sa:123@localhost:%s?dial+timeout=15&disableretry=false",
						port.Port())),
					Redacted: fmt.Sprintf("sqlserver://sa:********@localhost:%s?dial+timeout=15&disableretry=false",
						port.Port()),
					Verified: false,
				},
			},
			wantErr: false,
		},
		{
			name: "not found, in XML, missing password param (pwd is not valid)",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(`<add name="Sample2" value="SERVER=server_name;DATABASE=database_name;user=user_name;pwd=plaintextpassword;Timeout=120;MultipleActiveResultSets=True;" />`),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "found, verified, in XML",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(`<add name="test db" value="SERVER=localhost;PORT=%s;DATABASE=master;user=sa;password=%s;Timeout=120;MultipleActiveResultSets=True;" />`,
					port.Port(),
					password)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Redacted: fmt.Sprintf("sqlserver://sa:********@localhost:%s?database=master&dial+timeout=15&disableretry=false",
						port.Port()),
					Raw: []byte(password),
					RawV2: []byte(urlEncode(fmt.Sprintf("sqlserver://sa:%s@localhost:%s?database=master&dial+timeout=15&disableretry=false",
						password,
						port.Port()))),
					Verified: true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unreachable host",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("Server=unreachablehost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Raw:          []byte("P@ssw0rd!"),
					RawV2:        []byte("sqlserver://sa:P%40ssw0rd%21@unreachablehost?database=master&dial+timeout=15&disableretry=false"),
					Redacted:     "sqlserver://sa:********@unreachablehost?database=master&dial+timeout=15&disableretry=false",
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
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
				t.Errorf("SQLServer.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("SQLServer.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestSQLServer_FromChunk(t *testing.T) {
	secret := "Server=localhost;Initial Catalog=Demo;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;"
	inactiveSecret := "Server=localhost;User ID=sa;Password=123"

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name     string
		s        Scanner
		args     args
		want     []detectors.Result
		wantErr  bool
		mockFunc func()
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a sqlserver secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Redacted:     "sqlserver://sa:********@localhost?database=Demo&dial+timeout=15&disableretry=false",
					Verified:     true,
				},
			},
			wantErr: false,
			mockFunc: func() {
				ping = func(config msdsn.Config) (bool, error) {
					return true, nil
				}
			},
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a sqlserver secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Redacted:     "sqlserver://sa:********@localhost?dial+timeout=15&disableretry=false",
					Verified:     false,
				},
			},
			wantErr: false,
			mockFunc: func() {
				ping = func(config msdsn.Config) (bool, error) {
					return false, nil
				}
			},
		},
		{
			name: "not found, in XML, missing password param (pwd is not valid)",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(`<add name="Sample2" value="SERVER=server_name;DATABASE=database_name;user=user_name;pwd=plaintextpassword;encrypt=true;Timeout=120;MultipleActiveResultSets=True;" />`),
				verify: true,
			},
			want:    nil,
			wantErr: false,
			mockFunc: func() {
				ping = func(config msdsn.Config) (bool, error) {
					return true, nil
				}
			},
		},
		{
			name: "found, verified, in XML",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(`<add name="test db" value="SERVER=server_name;DATABASE=testdb;user=username;password=badpassword;encrypt=true;Timeout=120;MultipleActiveResultSets=True;" />`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Redacted:     "sqlserver://username:********@server_name?database=testdb&dial+timeout=15&disableretry=false&encrypt=true",
					Verified:     true,
				},
			},
			wantErr: false,
			mockFunc: func() {
				ping = func(config msdsn.Config) (bool, error) {
					if config.Host != "server_name" {
						return false, errors.New("invalid host")
					}

					if config.User != "username" {
						return false, errors.New("invalid database")
					}

					if config.Password != "badpassword" {
						return false, errors.New("invalid password")
					}

					if config.Database != "testdb" {
						return false, errors.New("invalid database")
					}

					return true, nil
				}
			},
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:     nil,
			wantErr:  false,
			mockFunc: func() {},
		},
	}

	// preserve the original function
	originalPing := ping

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("SQLServer.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
			}
			ignoreOpts := []cmp.Option{
				cmpopts.IgnoreFields(detectors.Result{}, "RawV2"),
				cmpopts.IgnoreUnexported(detectors.Result{}),
			}
			if diff := cmp.Diff(tt.want, got, ignoreOpts...); diff != "" {
				t.Errorf("SQLServer.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
				for _, g := range got {
					t.Error(g.Redacted)
				}
			}
		})
	}

	ping = originalPing
}

func urlEncode(s string) string {
	parsed, _ := url.Parse(s)
	return parsed.String()
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
