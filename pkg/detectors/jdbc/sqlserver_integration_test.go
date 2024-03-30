//go:build detectors && integration
// +build detectors,integration

package jdbc

import (
	"context"
	"fmt"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mssql"
)

func TestSqlServer(t *testing.T) {
	ctx := context.Background()

	sqlServerUser := "sa"
	sqlServerPass := gofakeit.Password(true, true, true, false, false, 10)
	sqlServerDB := "master"

	mssqlContainer, err := mssql.RunContainer(ctx,
		testcontainers.WithImage("mcr.microsoft.com/mssql/server:2022-RTM-GDR1-ubuntu-20.04"),
		mssql.WithAcceptEULA(),
		mssql.WithPassword(sqlServerPass),
	)
	if err != nil {
		t.Fatal(err)
	}

	defer mssqlContainer.Terminate(ctx)

	mssqlHost, err := mssqlContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	mssqlPort, err := mssqlContainer.MappedPort(ctx, "1433")
	if err != nil {
		t.Fatal(err)
	}

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
			input: "",
			want:  result{parseErr: true},
		},
		{
			input: fmt.Sprintf("//server=%s;port=%s;user id=%s;database=%s;password=%s",
				mssqlHost, mssqlPort.Port(), sqlServerUser, sqlServerDB, sqlServerPass),
			want: result{pingOk: true, pingDeterminate: true},
		},
		{
			input: "//server=badhost;user id=sa;database=master;password=",
			want:  result{pingOk: false, pingDeterminate: false},
		},
		{
			input: fmt.Sprintf("//%s;database=master;spring.datasource.password=%s;port=%s",
				mssqlHost, sqlServerPass, mssqlPort.Port()),
			want: result{pingOk: true, pingDeterminate: true},
		},
		{
			input: fmt.Sprintf("//%s;database=master;spring.datasource.password=badpassword;port=%s", mssqlHost, mssqlPort.Port()),
			want:  result{pingOk: false, pingDeterminate: true},
		},
		{
			input: fmt.Sprintf("//%s:%s;databaseName=master;user=%s;password=%s",
				mssqlHost, mssqlPort.Port(), sqlServerUser, sqlServerPass),
			want: result{pingOk: true, pingDeterminate: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			j, err := parseSqlServer(tt.input)

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
