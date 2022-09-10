//go:build detectors && integration
// +build detectors,integration

package jdbc

import (
	"bytes"
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	mysqlUser     = "coolGuy"
	mysqlPass     = "23201dabb56ca236f3dc6736c0f9afad"
	mysqlDatabase = "stuff"
)

func TestMySQL(t *testing.T) {
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
			input:    "//" + mysqlUser + ":" + mysqlPass + "@tcp(127.0.0.1:3306)/" + mysqlDatabase,
			wantPing: true,
		},
		{
			input:    "//wrongUser:wrongPass@tcp(127.0.0.1:3306)/" + mysqlDatabase,
			wantPing: false,
		},
		{
			input:    "//" + mysqlUser + ":wrongPass@tcp(127.0.0.1:3306)/" + mysqlDatabase,
			wantPing: false,
		},
		{
			input:    "//" + mysqlUser + ":" + mysqlPass + "@tcp(127.0.0.1:3306)/",
			wantPing: true,
		},
		{
			input:    "//" + mysqlUser + ":" + mysqlPass + "@tcp(127.0.0.1:3306)/wrongDB",
			wantPing: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			j, err := parseMySQL(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantPing, j.ping())
		})
	}
}

var mysqlDockerHash string

func startMySQL() error {
	cmd := exec.Command(
		"docker", "run", "--rm", "-p", "3306:3306",
		"-e", "MYSQL_ROOT_PASSWORD=403a96cff2a323f74bfb1c16992895be",
		"-e", "MYSQL_USER="+mysqlUser,
		"-e", "MYSQL_PASSWORD="+mysqlPass,
		"-e", "MYSQL_DATABASE="+mysqlDatabase,
		"-e", "MYSQL_ROOT_HOST=%",
		"-d", "mysql",
	)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	mysqlDockerHash = string(bytes.TrimSpace(out))
	select {
	case <-dockerLogLine(mysqlDockerHash, "socket: '/var/run/mysqld/mysqld.sock'  port: 3306"):
		return nil
	case <-time.After(30 * time.Second):
		stopMySQL()
		return errors.New("timeout waiting for mysql database to be ready")
	}
}

func stopMySQL() {
	exec.Command("docker", "kill", mysqlDockerHash).Run()
}
