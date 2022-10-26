//go:build detectors
// +build detectors

package sqlserver

import (
	"context"
	"fmt"
	"github.com/denisenkom/go-mssqldb/msdsn"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "RawV2")
			if diff := cmp.Diff(tt.want, got, ignoreOpts); diff != "" {
				t.Errorf("SQLServer.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}

	ping = originalPing
}

func TestSQLServer_pattern(t *testing.T) {
	if !pattern.Match([]byte(`builder.Services.AddDbContext<Database>(optionsBuilder => optionsBuilder.UseSqlServer("Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;"));`)) {
		t.Errorf("SQLServer.pattern: did not catched connection string from Program.cs")
	}
	if !pattern.Match([]byte(`{"ConnectionStrings": {"Demo": "Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;"}}`)) {
		t.Errorf("SQLServer.pattern: did not catched connection string from appsettings.json")
	}
	if !pattern.Match([]byte(`CONNECTION_STRING: Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true`)) {
		t.Errorf("SQLServer.pattern: did not catched connection string from .env")
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
