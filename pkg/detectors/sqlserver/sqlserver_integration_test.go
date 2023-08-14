//go:build detectors
// +build detectors

package sqlserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/denisenkom/go-mssqldb/msdsn"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	sqlServerPass     = "P@ssw0rd!"
	sqlServerUser     = "sa"
	sqlServerDatabase = "Demo"
)

func TestSQLServerIntegration_FromChunk(t *testing.T) {
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
					Redacted:     "sqlserver://sa:********@localhost?database=Demo&disableRetry=false",
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
					Redacted:     "sqlserver://sa:********@localhost?disableRetry=false",
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
					Redacted:     "sqlserver://username:********@server_name?database=testdb&disableRetry=false",
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
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "RawV2")
			if diff := cmp.Diff(tt.want, got, ignoreOpts); diff != "" {
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
		"-e", "MSSQL_SA_PASSWORD="+sqlServerPass,
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
