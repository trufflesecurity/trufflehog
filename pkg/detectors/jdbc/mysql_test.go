package jdbc

import "testing"

func Test_parseConnStr(t *testing.T) {
	type args struct {
		connStr string
	}
	tests := []struct {
		name          string
		args          args
		wantHostAndDB string
		wantParams    string
		wantErr       bool
	}{
		{
			name: "no params ",
			args: args{
				"//root:root@tcp(127.0.0.1:3306)/postgres",
			},
			wantHostAndDB: "//root:root@tcp(127.0.0.1:3306)/postgres",
			wantParams:    "",
			wantErr:       false,
		},
		{
			name: "params",
			args: args{
				"//root:root@tcp(127.0.0.1:3306)/postgres?allowAllFiles=true&clientFoundRows=1",
			},
			wantHostAndDB: "//root:root@tcp(127.0.0.1:3306)/postgres",
			wantParams:    "allowAllFiles=false&clientFoundRows=1",
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHostAndDB, gotParams, err := parseConnStr(tt.args.connStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConnStr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotHostAndDB != tt.wantHostAndDB {
				t.Errorf("parseConnStr() gotHostAndDB = %v, want %v", gotHostAndDB, tt.wantHostAndDB)
			}
			if gotParams != tt.wantParams {
				t.Errorf("parseConnStr() gotParams = %v, want %v", gotParams, tt.wantParams)
			}
		})
	}
}
