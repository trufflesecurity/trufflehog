package syslog

import (
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
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
						Hostname: "mymachine",
						Timestamp: time.Date(
							time.Now().Year(),
							time.October,
							11,
							22, 14, 15,
							0,
							time.UTC,
						).String(),
						Client:   "127.0.0.1:5140",
						Facility: "4",
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

func TestSource_monitorConnection_DebugLogsHideMessage(t *testing.T) {
	ctx, logs := logtest.DebugContext()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s := &Source{}
	conn, err := anypb.New(&sourcespb.Syslog{Format: "rfc5424"})
	require.NoError(t, err)
	require.NoError(t, s.Init(ctx, "test", 0, 0, false, conn, 1))

	// Send one message over an in-memory connection and wait for its chunk.
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	chunksChan := make(chan *sources.Chunk, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.monitorConnection(ctx, server, chunksChan)
	}()

	message := "<165>1 2003-10-11T22:14:15.003Z host app - ID47 - password=hunter2"
	_, err = client.Write([]byte(message))
	require.NoError(t, err)
	<-chunksChan
	cancel()
	<-done

	// The debug line is written, but the message itself never shows up in the logs.
	assert.Equal(t, 1, logs.FilterMessage("received syslog message").Len())
	for _, entry := range logs.All() {
		assert.NotContains(t, entry.Message, "hunter2")
		assert.NotContains(t, fmt.Sprint(entry.ContextMap()), "hunter2")
	}
}
