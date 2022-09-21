//go:build detectors
// +build detectors

package jdbc

import (
	"context"
	"os"
	"testing"

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
			name: "sqlite unverified",
			args: args{
				ctx:    context.Background(),
				data:   []byte("jdbc:sqlite::memory:"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     false,
					Redacted:     "jdbc:sqlite::memory:",
				},
			},
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

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
