//go:build detectors
// +build detectors

package jdbc

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

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
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Jdbc.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestJdbc_FromDataWithIgnorePattern(t *testing.T) {
	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name           string
		args           args
		want           []detectors.Result
		ignorePatterns []string
		wantErr        bool
	}{
		{
			name: "not found",
			args: args{
				ctx:    context.Background(),
				data:   []byte("jdbc:sqlite::secretpattern:"),
				verify: false,
			},
			want: nil,
			ignorePatterns: []string{
				".*secretpattern.*",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(WithIgnorePattern(tt.ignorePatterns))
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Jdbc.FromDataWithConfig() error = %v, wantErr %v", err, tt.wantErr)
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
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Jdbc.FromDataWithConfig() %s diff: (-got +want)\n%s", tt.name, diff)
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
