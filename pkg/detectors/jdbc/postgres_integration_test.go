//go:build detectors && integration
// +build detectors,integration

package jdbc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	type result struct {
		parseErr        bool
		pingOk          bool
		pingDeterminate bool
	}
	tests := []struct {
		input string
		want  result
	}{
		{
			input: "//localhost:5432/foo?sslmode=disable&password=" + postgresPass,
			want:  result{pingOk: true, pingDeterminate: true},
		},
		{
			input: fmt.Sprintf("//postgres:%s@localhost:5432/foo?sslmode=disable", postgresPass),
			want:  result{pingOk: true, pingDeterminate: true},
		},
		{
			input: "//localhost:5432/foo?sslmode=disable&user=" + postgresUser + "&password=" + postgresPass,
			want:  result{pingOk: true, pingDeterminate: true},
		},
		{
			input: fmt.Sprintf("//%s:%s@localhost:5432/foo?sslmode=disable", postgresUser, postgresPass),
			want:  result{pingOk: true, pingDeterminate: true},
		},
		{
			input: "//localhost/foo?sslmode=disable&port=5432&password=" + postgresPass,
			want:  result{pingOk: true, pingDeterminate: true},
		},
		{
			input: "//localhost:5432/foo?password=" + postgresPass,
			want:  result{pingOk: false, pingDeterminate: false},
		},
		{
			input: "//localhost:5432/foo?sslmode=disable&password=foo",
			want:  result{pingOk: false, pingDeterminate: true},
		},
		{
			input: "//localhost:5432/foo?sslmode=disable&user=foo&password=" + postgresPass,
			want:  result{pingOk: false, pingDeterminate: true},
		},
		{
			input: "//badhost:5432/foo?sslmode=disable&user=foo&password=" + postgresPass,
			want:  result{pingOk: false, pingDeterminate: false},
		},
		{
			input: "invalid",
			want:  result{parseErr: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			j, err := parsePostgres(tt.input)

			if err != nil {
				got := result{parseErr: true}
				assert.Equal(t, tt.want, got)
				return
			}

			pr := j.ping(context.Background())

			got := result{pingOk: pr.err == nil, pingDeterminate: pr.determinate}
			assert.Equal(t, tt.want, got)
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
