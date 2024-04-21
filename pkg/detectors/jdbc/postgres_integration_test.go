//go:build detectors && integration
// +build detectors,integration

package jdbc

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/go-cmp/cmp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPostgres(t *testing.T) {
	type result struct {
		ParseErr        bool
		PingOk          bool
		PingDeterminate bool
	}

	user := gofakeit.Username()
	pass := gofakeit.Password(true, true, true, false, false, 32)
	dbName := gofakeit.Word()

	t.Log("user: ", user)
	t.Log("dbName: ", dbName)

	ctx := context.Background()
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:13-alpine"),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(user),
		postgres.WithPassword(pass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}

	host, err := postgresContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := postgresContainer.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		log.Fatalf("failed to start container: %s", err)
	}
	defer postgresContainer.Terminate(ctx)

	tests := []struct {
		name  string
		input string
		want  result
	}{
		{
			name:  "invalid password",
			input: fmt.Sprintf("//%s:%s/foo?sslmode=disable&password=foo", host, port.Port()),
			want:  result{PingOk: false, PingDeterminate: true},
		},
		{
			name:  "valid password - no user name",
			input: fmt.Sprintf("//%s:%s/foo?sslmode=disable&password=%s", host, port.Port(), pass),
			want:  result{PingOk: false, PingDeterminate: true},
		},
		{
			name:  "exact username and password, wrong db",
			input: fmt.Sprintf("//%s:%s@%s:%s/foo?sslmode=disable", user, pass, host, port.Port()),
			want:  result{PingOk: true, PingDeterminate: true},
		},
		{
			name:  "exact username and password, no db",
			input: fmt.Sprintf("//%s:%s@%s:%s?sslmode=disable", user, pass, host, port.Port()),
			want:  result{PingOk: true, PingDeterminate: true},
		},
		{
			name:  "invalid user name",
			input: fmt.Sprintf("//%s:%s/foo?sslmode=disable&user=foo&password=%s", host, port.Port(), pass),
			want:  result{PingOk: false, PingDeterminate: true},
		},
		{
			name:  "invalid hostname",
			input: fmt.Sprintf("//badhost:%s/foo?sslmode=disable&user=foo&password=%s", port.Port(), pass),
			want:  result{PingOk: false, PingDeterminate: false},
		},
		{
			name:  "no username, password",
			input: fmt.Sprintf("//%s:%s/foo?password=%s", host, port.Port(), pass),
			want:  result{PingOk: false, PingDeterminate: false},
		},
		{
			name:  "db, password - no username",
			input: fmt.Sprintf("//%s:%s/foo?sslmode=disable&password=%s", host, port.Port(), pass),
			want:  result{PingOk: false, PingDeterminate: true},
		},
		{
			name:  "invalid format",
			input: "invalid",
			want:  result{ParseErr: true},
		},
		{
			name:  "normal connect with generated username and password",
			input: fmt.Sprintf("//%s:%s@%s:%s/%s?sslmode=disable", user, pass, host, port.Port(), dbName),
			want:  result{PingOk: true, PingDeterminate: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := parsePostgres(tt.input)
			if err != nil {
				got := result{ParseErr: true}

				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("%s: (-want +got)\n%s", tt.name, diff)
					t.Errorf("error is: %v", err)
				}
				return
			}

			pr := j.ping(ctx)

			got := result{PingOk: pr.err == nil, PingDeterminate: pr.determinate}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("%s: (-want +got)\n%s", tt.name, diff)
				t.Errorf("error is: %v", pr.err)
			}
		})
	}
}
