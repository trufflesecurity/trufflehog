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
	postgresUser = "postgres"
	postgresPass = "23201dabb56ca236f3dc6736c0f9afad"
)

func TestPostgres(t *testing.T) {
	tests := []struct {
		input    string
		wantErr  bool
		wantPing bool
	}{
		{
			input:    "//localhost:5432/foo?sslmode=disable&password=" + postgresPass,
			wantPing: true,
		},
		{
			input:    "//localhost:5432/foo?sslmode=disable&user=" + postgresUser + "&password=" + postgresPass,
			wantPing: true,
		},
		{
			input:    "//localhost/foo?sslmode=disable&port=5432&password=" + postgresPass,
			wantPing: true,
		},
		{
			input:    "//localhost:5432/foo?password=" + postgresPass,
			wantPing: false,
		},
		{
			input:    "//localhost:5432/foo?sslmode=disable&password=foo",
			wantPing: false,
		},
		{
			input:    "//localhost:5432/foo?sslmode=disable&user=foo&password=" + postgresPass,
			wantPing: false,
		},
		{
			input:   "invalid",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			j, err := parsePostgres(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantPing, j.ping())
		})
	}
}

var postgresDockerHash string

func startPostgres() error {
	cmd := exec.Command(
		"docker", "run", "--rm", "-p", "5432:5432",
		"-e", "POSTGRES_PASSWORD="+postgresPass,
		"-e", "POSTGRES_USER="+postgresUser,
		"-d", "postgres",
	)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	postgresDockerHash = string(bytes.TrimSpace(out))
	select {
	case <-dockerLogLine(postgresDockerHash, "PostgreSQL init process complete; ready for start up."):
		return nil
	case <-time.After(30 * time.Second):
		stopPostgres()
		return errors.New("timeout waiting for postgres database to be ready")
	}
}

func stopPostgres() {
	exec.Command("docker", "kill", postgresDockerHash).Run()
}
