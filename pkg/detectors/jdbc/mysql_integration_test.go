//go:build detectors && integration
// +build detectors,integration

package jdbc

import (
	"context"
	"fmt"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
)

func TestMySQL(t *testing.T) {
	mysqlUser := gofakeit.Username()
	mysqlPass := gofakeit.Password(true, true, true, false, false, 10)
	mysqlDatabase := gofakeit.Word()

	ctx := context.Background()

	mysqlC, err := mysql.RunContainer(ctx,
		mysql.WithDatabase(mysqlDatabase),
		mysql.WithUsername(mysqlUser),
		mysql.WithPassword(mysqlPass),
	)
	if err != nil {
		t.Fatal(err)
	}

	defer mysqlC.Terminate(ctx)

	host, err := mysqlC.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := mysqlC.MappedPort(ctx, "3306")
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		ParseErr        bool
		PingOk          bool
		PingDeterminate bool
	}
	tests := []struct {
		name  string
		input string
		want  result
	}{
		{
			name:  "empty",
			input: "",
			want:  result{ParseErr: true},
		},
		{
			name:  "all good",
			input: fmt.Sprintf("//%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPass, host, port.Port(), mysqlDatabase),
			want:  result{PingOk: true, PingDeterminate: true},
		},
		{
			name:  "wrong creds",
			input: fmt.Sprintf("//wrongUser:wrongPassword@tcp(%s:%s)/%s", host, port.Port(), mysqlDatabase),
			want:  result{PingOk: false, PingDeterminate: true},
		},
		{
			name:  "wrong pass",
			input: fmt.Sprintf("//%s:wrongPass@tcp(%s:%s)/%s", mysqlUser, host, port.Port(), mysqlDatabase),
			want:  result{PingOk: false, PingDeterminate: true},
		},
		{
			name:  "no db",
			input: fmt.Sprintf("//%s:%s@tcp(%s:%s)/", mysqlUser, mysqlPass, host, port.Port()),
			want:  result{PingOk: true, PingDeterminate: true},
		},
		{
			name:  "wrong db",
			input: fmt.Sprintf("//%s:%s@tcp(%s:%s)/wrongDB", mysqlUser, mysqlPass, host, port.Port()),
			want:  result{PingOk: true, PingDeterminate: true},
		},
		{
			name:  "jdbc format",
			input: fmt.Sprintf("//%s:%s@%s:%s/%s", mysqlUser, mysqlPass, host, port.Port(), mysqlDatabase),
			want:  result{PingOk: true, PingDeterminate: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			j, err := parseMySQL(tt.input)

			if err != nil {
				got := result{ParseErr: true}
				assert.Equal(t, tt.want, got)
				return
			}

			pr := j.ping(context.Background())

			got := result{PingOk: pr.err == nil, PingDeterminate: pr.determinate}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("%s: (-want +got)\n%s", tt.name, diff)
				t.Errorf("error is: %v", pr.err)
			}
		})
	}
}
