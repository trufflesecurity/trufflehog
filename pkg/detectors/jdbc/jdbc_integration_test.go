//go:build detectors && integration
// +build detectors,integration

package jdbc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestMain(m *testing.M) {
	code, err := runMain(m)
	if err != nil {
		panic(err)
	}
	os.Exit(code)
}

func runMain(m *testing.M) (int, error) {
	if err := startPostgres(); err != nil {
		return 0, err
	}
	defer stopPostgres()
	if err := startMySQL(); err != nil {
		return 0, err
	}
	defer stopMySQL()
	return m.Run(), nil
}

func dockerLogLine(hash string, needle string) chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		for {
			out, err := exec.Command("docker", "logs", hash).CombinedOutput()
			if err != nil {
				panic(err)
			}
			if strings.Contains(string(out), needle) {
				ch <- struct{}{}
				return
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return ch
}

func TestJdbcVerified(t *testing.T) {
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
				ctx:    context.Background(),
				data:   []byte(`jdbc connection string: jdbc:postgresql://localhost:5432/foo?sslmode=disable&password=` + postgresPass),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     true,
					Redacted:     "jdbc:postgresql://localhost:5432/foo?sslmode=disable&password=" + strings.Repeat("*", len(postgresPass)),
				},
			},
			wantErr: false,
		},
		{
			name: "mysql verified",
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`CONN="jdbc:mysql://%s:%s@tcp(127.0.0.1:3306)/%s"`, mysqlUser, mysqlPass, mysqlDatabase)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_JDBC,
					Verified:     true,
					Redacted:     fmt.Sprintf(`jdbc:mysql://%s:%s@tcp(127.0.0.1:3306)/%s`, mysqlUser, strings.Repeat("*", len(mysqlPass)), mysqlDatabase),
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
