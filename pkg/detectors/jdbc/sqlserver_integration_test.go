//go:build detectors && integration
// +build detectors,integration

package jdbc

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	sqlServerPass     = "Secr3tP@s5w0rd"
	sqlServerUser     = "sa"
	sqlServerDatabase = "master"
)

func TestSqlServer(t *testing.T) {
	tests := []struct {
		input    string
		wantErr  bool
		wantPing bool
	}{
		{
			input:   "",
			wantErr: true,
		},
		{
			input:    "//odbc:server=localhost;user id=sa;database=master;password=" + sqlServerPass,
			wantPing: true,
		},
		{
			input:    "//localhost;database= master;spring.datasource.password=" + sqlServerPass,
			wantPing: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			j, err := parseSqlServer(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantPing, j.ping(context.Background()))
		})
	}
}

var sqlServerDockerHash string

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
		return errors.New("timeout waiting for mysql database to be ready")
	}
}

func stopSqlServer() {
	exec.Command("docker", "kill", sqlServerDockerHash).Run()
}
