//go:build detectors && integration
// +build detectors,integration

package redis

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/kylelemons/godebug/pretty"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func setupACLConfigFile(redisUser, redisPass string) (*os.File, error) {

	aclString := fmt.Sprintf(`
		user default on >%s ~* +@all
		user %s on >%s ~* +@all
	`, redisPass, redisUser, redisPass)

	aclFile, err := ioutil.TempFile("", "redis_users.acl")
	if err != nil {
		return nil, err
	}

	if _, err := aclFile.Write([]byte(aclString)); err != nil {
		return nil, err
	}

	return aclFile, nil
}

func TestRedisIntegration_FromChunk(t *testing.T) {
	redisUser := gofakeit.Username()
	redisPass := gofakeit.Password(true, true, true, false, false, 10)

	ctx := context.Background()

	aclFile, err := setupACLConfigFile(redisUser, redisPass)
	if err != nil {
		t.Fatal(err)
	}
	defer aclFile.Close()

	redisContainerRequest := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.BindMount(aclFile.Name(), "/usr/local/etc/redis/users.acl"),
		},
		Cmd:        []string{"redis-server", "--aclfile", "/usr/local/etc/redis/users.acl"},
		WaitingFor: wait.ForLog("Ready to accept connections").WithStartupTimeout(10 * time.Second),
	}

	redisC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: redisContainerRequest,
		Started:          true,
	})

	if err != nil {
		t.Fatal(err)
	}

	port, err := redisC.MappedPort(ctx, "6379")
	if err != nil {
		t.Fatal(err)
	}
	host, err := redisC.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	defer redisC.Terminate(ctx)

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
			name: "bad scheme",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("file://user:pass@foo.com:123/wh/at/ever"),
				verify: true,
			},
			wantErr: false,
		},
		{
			name: "unverified Redis",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("redis://%s:%s@%s:%s", redisUser, "wrongpass", host, port.Port())),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Redis,
					Verified:     false,
					Redacted:     fmt.Sprintf("redis://%s:*******@%s:%s", redisUser, host, port.Port()),
				},
			},
			wantErr: false,
		},
		{
			name: "verified Redis",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("redis://%s:%s@%s:%s", redisUser, redisPass, host, port.Port())),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Redis,
					Verified:     true,
					Redacted:     fmt.Sprintf("redis://%s:*******@%s:%s", redisUser, host, port.Port()),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("URI.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("URI.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}
