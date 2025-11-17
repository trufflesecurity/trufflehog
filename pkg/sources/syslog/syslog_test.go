package syslog

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

func TestSource_parseSyslogMetadata(t *testing.T) {
	type args struct {
		format string
		input  []byte
		remote string
	}
	tests := []struct {
		name    string
		args    args
		want    *source_metadatapb.MetaData
		wantErr bool
	}{
		{
			name: "success - rfc5424",
			args: args{
				format: "rfc5424",
				input:  []byte("<14>1 2025-08-05T12:00:00Z my-host my-app 1234 ID47 - Test message"),
				remote: "127.0.0.1:5140",
			},
			want: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Syslog{
					Syslog: &source_metadatapb.Syslog{
						Hostname:  "my-host",
						Appname:   "my-app",
						Procid:    "1234",
						Timestamp: "2025-08-05 12:00:00 +0000 UTC",
						Client:    "127.0.0.1:5140",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "success - rfc5424",
			args: args{
				format: "rfc5424",
				input:  []byte("<34>1 2023-08-05T14:30:22.123Z webserver nginx 1234 access-log - 192.168.1.100 GET /index.html 200"),
				remote: "127.0.0.1:5140",
			},
			want: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Syslog{
					Syslog: &source_metadatapb.Syslog{
						Hostname:  "webserver",
						Appname:   "nginx",
						Procid:    "1234",
						Timestamp: "2023-08-05 14:30:22.123 +0000 UTC",
						Client:    "127.0.0.1:5140",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "success - rfc3164",
			args: args{
				format: "rfc3164",
				input:  []byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"),
				remote: "127.0.0.1:5140",
			},
			want: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Syslog{
					Syslog: &source_metadatapb.Syslog{
						Hostname:  "mymachine",
						Timestamp: "2025-10-11 22:14:15 +0000 UTC",
						Client:    "127.0.0.1:5140",
						Facility:  "4",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "fail - wrong format",
			args: args{
				format: "rfc5424",
				input:  []byte("Test message"),
				remote: "127.0.0.1:5140",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Source{}

			conn, err := anypb.New(&sourcespb.Syslog{
				Format: tt.args.format,
			})
			assert.NoError(t, err)

			err = s.Init(context.Background(), "test", 0, 0, false, conn, 5)
			assert.NoError(t, err)

			got, err := s.parseSyslogMetadata(tt.args.input, tt.args.remote)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.parseSyslogMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Source.parseSyslogMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}
