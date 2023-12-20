//go:build detectors
// +build detectors

package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var postgresDockerHash string

const (
	postgresUser = "postgres"
	postgresPass = "23201dabb56ca236f3dc6736c0f9afad"
	postgresHost = "localhost"
	postgresPort = "5433"

	inactiveUser = "inactive"
	inactivePass = "inactive"
	inactivePort = "61000"
	inactiveHost = "192.0.2.0"
)

func TestPostgres_FromChunk(t *testing.T) {
	startPostgres()
	defer stopPostgres()

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		s       Scanner
		args    args
		want    []detectors.Result
		wantErr bool
	}{
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
		{
			name: "found with seperated credentials, verified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(`
					POSTGRES_USER=%s
					POSTGRES_PASSWORD=%s
					POSTGRES_ADDRESS=%s
					POSTGRES_PORT=%s
					`, postgresUser, postgresPass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found with single line credentials, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, postgresPass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found with json credentials, verified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					`DB_CONFIG={"user": "%s", "password": "%s", "host": "%s", "port": "%s", "database": "postgres"}`, postgresUser, postgresPass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found with seperated credentials, unverified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(`
					POSTGRES_USER=%s
					POSTGRES_PASSWORD=%s
					POSTGRES_ADDRESS=%s
					POSTGRES_PORT=%s
					`, postgresUser, inactivePass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "found with single line credentials, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, inactivePass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "found with json credentials, unverified - inactive password",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					`DB_CONFIG={"user": "%s", "password": "%s", "host": "%s", "port": "%s", "database": "postgres"}`, postgresUser, inactivePass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "found with json credentials, unverified - inactive user",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					`DB_CONFIG={"user": "%s", "password": "%s", "host": "%s", "port": "%s", "database": "postgres"}`, inactiveUser, postgresPass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified due to error - inactive port",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, postgresPass, postgresHost, inactivePort)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     false,
				}
				r.SetVerificationError(errors.New("connection refused"))
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
		// TODO: This test seems take a long time to run (70s+) even with the timeout set to 1s. It's not clear why.
		{
			name: "found, unverified due to error - inactive host",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, postgresPass, inactiveHost, postgresPort)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     false,
				}
				r.SetVerificationError(errors.New("operation timed out"))
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("postgres.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				gotErr := ""
				if got[i].VerificationError() != nil {
					gotErr = got[i].VerificationError().Error()
				}
				wantErr := ""
				if tt.want[i].VerificationError() != nil {
					wantErr = tt.want[i].VerificationError().Error()
				}
				if gotErr != wantErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.want[i].VerificationError(), got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Postgres.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
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

func startPostgres() error {
	cmd := exec.Command(
		"docker", "run", "--rm", "-p", postgresPort+":"+defaultPort,
		"-e", "POSTGRES_PASSWORD="+postgresPass,
		"-e", "POSTGRES_USER="+postgresUser,
		"-d", "postgres",
	)
	fmt.Println(cmd.String())
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

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
