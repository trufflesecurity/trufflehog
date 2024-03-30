//go:build detectors && integration
// +build detectors,integration

package jdbc

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mssql"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestJdbcVerified(t *testing.T) {
	ctx := context.Background()

	postgresUser := gofakeit.Username()
	postgresPass := gofakeit.Password(true, true, true, false, false, 10)
	postgresDB := gofakeit.Word()
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:13-alpine"),
		postgres.WithDatabase(postgresDB),
		postgres.WithUsername(postgresUser),
		postgres.WithPassword(postgresPass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer postgresContainer.Terminate(ctx)

	postgresHost, err := postgresContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	postgresPort, err := postgresContainer.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatal(err)
	}

	mysqlUser := gofakeit.Username()
	mysqlPass := gofakeit.Password(true, true, true, false, false, 10)
	mysqlDatabase := gofakeit.Word()
	mysqlC, err := mysql.RunContainer(ctx,
		mysql.WithDatabase(mysqlDatabase),
		mysql.WithUsername(mysqlUser),
		mysql.WithPassword(mysqlPass),
	)
	if err != nil {
		t.Fatal(err)
	}

	defer mysqlC.Terminate(ctx)

	mysqlHost, err := mysqlC.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mysqlPort, err := mysqlC.MappedPort(ctx, "3306")
	if err != nil {
		t.Fatal(err)
	}

	sqlServerPass := gofakeit.Password(true, true, true, false, false, 10)
	sqlServerDatabase := "master"

	mssqlContainer, err := mssql.RunContainer(ctx,
		testcontainers.WithImage("mcr.microsoft.com/mssql/server:2022-RTM-GDR1-ubuntu-20.04"),
		mssql.WithAcceptEULA(),
		mssql.WithPassword(sqlServerPass),
	)
	if err != nil {
		t.Fatal(err)
	}

	defer mssqlContainer.Terminate(ctx)

	sqlServerHost, err := mssqlContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	sqlServerPort, err := mssqlContainer.MappedPort(ctx, "1433")
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "postgres verified",
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf("jdbc connection string: jdbc:postgresql://%s:%s/%s?sslmode=disable&password=%s&user=%s",
					postgresHost, postgresPort.Port(), postgresDB, postgresPass, postgresUser)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     true,
					Redacted: fmt.Sprintf("jdbc:postgresql://%s:%s/%s?sslmode=disable&password=%s&user=%s",
						postgresHost, postgresPort.Port(), postgresDB, strings.Repeat("*", len(postgresPass)), postgresUser),
				},
			},
			wantErr: false,
		},
		{
			name: "mysql verified",
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(`CONN="jdbc:mysql://%s:%s@tcp(%s:%s)/%s"`,
					mysqlUser, mysqlPass, mysqlHost, mysqlPort.Port(), mysqlDatabase)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     true,
					Redacted: fmt.Sprintf(`jdbc:mysql://%s:%s@tcp(%s:%s)/%s`,
						mysqlUser, strings.Repeat("*", len(mysqlPass)), mysqlHost, mysqlPort.Port(), mysqlDatabase),
				},
			},
			wantErr: false,
		},
		{
			name: "sql server verified",
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf("jdbc:sqlserver://odbc:server=%s;port=%s;database=%s;password=%s",
					sqlServerHost, sqlServerPort.Port(), sqlServerDatabase, sqlServerPass)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     true,
					Redacted: fmt.Sprintf("jdbc:sqlserver://odbc:server=%s;port=%s;database=%s;password=%s",
						sqlServerHost, sqlServerPort.Port(), sqlServerDatabase, strings.Repeat("*", len(sqlServerPass))),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if os.Getenv("FORCE_PASS_DIFF") == "true" {
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Jdbc.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}
