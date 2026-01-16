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
	postgresContainer, err := postgres.Run(ctx,
		"postgres:13-alpine",
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
	mysqlC, err := mysql.Run(ctx,
		"mysql:8.0.36",
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

	mssqlContainer, err := mssql.Run(ctx,
		"mcr.microsoft.com/azure-sql-edge",
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
					AnalysisInfo: map[string]string{
						"connection_string": fmt.Sprintf("jdbc:postgresql://%s:%s/%s?sslmode=disable&password=%s&user=%s",
							postgresHost, postgresPort.Port(), postgresDB, postgresPass, postgresUser),
					},
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
					AnalysisInfo: map[string]string{
						"connection_string": fmt.Sprintf(`jdbc:mysql://%s:%s@tcp(%s:%s)/%s`,
							mysqlUser, mysqlPass, mysqlHost, mysqlPort.Port(), mysqlDatabase),
					},
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
					AnalysisInfo: map[string]string{
						"connection_string": fmt.Sprintf("jdbc:sqlserver://odbc:server=%s;port=%s;database=%s;password=%s",
							sqlServerHost, sqlServerPort.Port(), sqlServerDatabase, sqlServerPass),
					},
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

func TestJdbc_FromChunk(t *testing.T) {
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
			name: "found, unverified",
			args: args{
				ctx:    context.Background(),
				data:   []byte(`jdbc connection string: jdbc:mysql://hello.test.us-east-1.rds.amazonaws.com:3306/testdb?password=testpassword <-`),
				verify: false,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     false,
					Redacted:     "jdbc:mysql://hello.test.us-east-1.rds.amazonaws.com:3306/testdb?password=************",
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified numeric password",
			args: args{
				ctx:    context.Background(),
				data:   []byte(`jdbc connection string: jdbc:postgresql://host:5342/testdb?password=123456 <-`),
				verify: false,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     false,
					Redacted:     "jdbc:postgresql://host:5342/testdb?password=******",
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: false,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "found double quoted string, unverified",
			args: args{
				ctx:    context.Background(),
				data:   []byte(`CONN="jdbc:postgres://hello.test.us-east-1.rds.amazonaws.com:3306/testdb?password=testpassword"`),
				verify: false,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     false,
					Redacted:     "jdbc:postgres://hello.test.us-east-1.rds.amazonaws.com:3306/testdb?password=************",
				},
			},
			wantErr: false,
		},
		{
			name: "found single quoted string, unverified",
			args: args{
				ctx:    context.Background(),
				data:   []byte(`CONN='jdbc:postgres://hello.test.us-east-1.rds.amazonaws.com:3306/testdb?password=testpassword'`),
				verify: false,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     false,
					Redacted:     "jdbc:postgres://hello.test.us-east-1.rds.amazonaws.com:3306/testdb?password=************",
				},
			},
			wantErr: false,
		},
		{
			name: "sqlserver, unverified",
			args: args{
				ctx:    context.Background(),
				data:   []byte(`jdbc:sqlserver://a.b.c.net;database=database-name;spring.datasource.password=super-secret-password`),
				verify: false,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     false,
					Redacted:     "jdbc:sqlserver://a.b.c.net;database=database-name;spring.datasource.password=*********************",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Jdbc.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if os.Getenv("FORCE_PASS_DIFF") == "true" {
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
				got[i].AnalysisInfo = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Jdbc.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestJdbc_Redact(t *testing.T) {
	tests := []struct {
		name string
		conn string
		want string
	}{
		{
			name: "basic auth'",
			conn: "//user:secret@tcp(127.0.0.1:3306)/",
			want: "//user:******@tcp(127.0.0.1:3306)/",
		},
		{
			name: "basic auth including raw string 'pass'",
			conn: "//wrongUser:wrongPass@tcp(127.0.0.1:3306)/",
			want: "//wrongUser:*********@tcp(127.0.0.1:3306)/",
		},
		{
			name: "basic auth including raw string 'pass' with unfortunate db name",
			conn: "//wrongUser:wrongPass@tcp(127.0.0.1:3306)/passwords",
			want: "//wrongUser:*********@tcp(127.0.0.1:3306)/passwords",
		},
		{
			name: "url param-style",
			conn: "jdbc:postgresql://localhost:5432/foo?sslmode=disable&password=p@ssw04d",
			want: "jdbc:postgresql://localhost:5432/foo?sslmode=disable&password=********",
		},
		{
			name: "odbc-style without server",
			conn: "//odbc:server=localhost;user id=sa;database=master;password=/p?s=sw&rd",
			want: "//odbc:server=localhost;user id=sa;database=master;password=**********",
		},
		{
			name: "odbc-style with server",
			conn: "jdbc:sqlserver://a.b.c.net;database=database-name;spring.datasource.password=super-secret-password",
			want: "jdbc:sqlserver://a.b.c.net;database=database-name;spring.datasource.password=*********************",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tryRedactAnonymousJDBC(tt.conn)
			assert.Equal(t, tt.want, got)
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
