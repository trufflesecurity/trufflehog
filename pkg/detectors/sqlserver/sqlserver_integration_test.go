//go:build detectors && integration
// +build detectors,integration

package sqlserver

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestSQLServerIntegration_FromChunk(t *testing.T) {
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
				data:   []byte("Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Raw:          []byte("P@ssw0rd!"),
					RawV2:        []byte("sqlserver://sa:P%40ssw0rd%21@localhost?database=master&disableRetry=false"),
					Redacted:     "sqlserver://sa:********@localhost?database=master&disableRetry=false",
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("Server=localhost;User ID=sa;Password=123"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Raw:          []byte("123"),
					RawV2:        []byte("sqlserver://sa:123@localhost?disableRetry=false"),
					Redacted:     "sqlserver://sa:********@localhost?disableRetry=false",
					Verified:     false,
				},
			},
			wantErr: false,
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
		},
		{
			name: "found, verified, in XML",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(`<add name="test db" value="SERVER=localhost;DATABASE=master;user=sa;password=P@ssw0rd!;encrypt=true;Timeout=120;MultipleActiveResultSets=True;" />`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SQLServer,
					Redacted:     "sqlserver://sa:********@localhost?database=master&disableRetry=false",
					Raw:          []byte("P@ssw0rd!"),
					RawV2:        []byte("sqlserver://sa:P%40ssw0rd%21@localhost?database=master&disableRetry=false"),
					Verified:     true,
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
					RawV2:        []byte("sqlserver://sa:P%40ssw0rd%21@unreachablehost?database=master&disableRetry=false"),
					Redacted:     "sqlserver://sa:********@unreachablehost?database=master&disableRetry=false",
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

	if err := startSqlServer(); err != nil {
		t.Fatalf("could not start sql server for integration testing: %v", err)
	}
	defer stopSqlServer()

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

var sqlServerDockerHash string

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

func startSqlServer() error {
	cmd := exec.Command(
		"docker", "run", "--rm", "-p", "1433:1433",
		"-e", "ACCEPT_EULA=1",
		"-e", "MSSQL_SA_PASSWORD=P@ssw0rd!",
		"-d", "mcr.microsoft.com/azure-sql-edge",
	)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	sqlServerDockerHash = string(bytes.TrimSpace(out))
	select {
	case <-dockerLogLine(sqlServerDockerHash, "EdgeTelemetry starting up"):
		return nil
	case <-time.After(30 * time.Second):
		stopSqlServer()
		return errors.New("timeout waiting for sql server database to be ready")
	}
}

func stopSqlServer() {
	exec.Command("docker", "kill", sqlServerDockerHash).Run()
}
