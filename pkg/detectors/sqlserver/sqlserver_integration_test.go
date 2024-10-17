//go:build detectors && integration
// +build detectors,integration

package sqlserver

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func urlEncode(s string) string {
	parsed, _ := url.Parse(s)
	return parsed.String()
}
